const std = @import("std");
const assert = std.debug.assert;
const common = @import("../common.zig");
const TODO = common.TODO;
const mem = @import("mem.zig");
const log = std.log.scoped(.heap);
const math = std.math;
const page_size = std.mem.page_size;
const StackTrace = std.builtin.StackTrace;
const Allocator = std.mem.Allocator;

/// The kernel page allocator. It is just a wrapper around the VMM, allocating
/// kernel writable pages. Because of that, it won't work until the VMM is
/// initialized.
pub const page_allocator = Allocator{
    .ptr = undefined,
    .vtable = &PageAllocator.vtable,
};

var heap_allocator_state = HeapAllocator.init();
pub const heap_allocator = heap_allocator_state.allocator();

var block_allocator_state = BlockAllocator.init();
pub const block_allocator = block_allocator_state.allocator();

var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){
    .backing_allocator = mem.heap.page_allocator,
};
pub const gpa_allocator = gpa.allocator();

pub fn initHeapAllocator() void {
    heap_allocator_state.base = mem.layout.kernel_brk;
}

pub const HeapAllocator = struct {
    base: usize,
    used: usize,
    size: usize,

    pub fn init() HeapAllocator {
        return HeapAllocator{
            .base = 0,
            .used = 0,
            .size = 0,
        };
    }

    pub fn allocator(self: *HeapAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn more(self: *HeapAllocator, num_pages: usize) Allocator.Error!void {
        const ret = try mem.vmm.allocPages(num_pages, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        });
        assert(ret == self.base + self.size);
        self.size += num_pages * std.mem.page_size;
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        log2_ptr_align: u8,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *HeapAllocator = @ptrCast(@alignCast(ctx));
        const ret_offset = std.mem.alignForwardLog2(self.used, log2_ptr_align);
        const free_bytes = self.size - ret_offset;
        if (len > free_bytes) {
            const needed_memory = mem.alignPageForward(len - free_bytes);
            const num_pages = @divExact(needed_memory, std.mem.page_size);
            self.more(num_pages) catch return null;
        }

        self.used = ret_offset + len;
        assert(self.used <= self.size);
        const ret = self.base + ret_offset;
        log.debug("heap allocator: returns 0x{x}\n", .{ret});
        return @as([*]u8, @ptrFromInt(ret));
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ctx;
        _ = buf;
        _ = log2_buf_align;
        _ = new_len;
        _ = ret_addr;
        TODO();
    }

    fn isLastAllocation(self: HeapAllocator, buf: []u8) bool {
        return self.base + self.used - buf.len == @intFromPtr(buf.ptr);
    }

    fn free(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        ret_addr: usize,
    ) void {
        _ = log2_buf_align;
        _ = ret_addr;
        const self: *HeapAllocator = @ptrCast(@alignCast(ctx));
        if (self.isLastAllocation(buf)) {
            // Rollback
            self.used -= buf.len;
        }
        log.debug("heap allocator: frees {*}\n", .{buf});
    }
};

pub const BlockAllocator = struct {
    /// Heads of the linked lists of free blocks.
    list_heads: [BLOCK_SIZES.len]?*Block,

    /// The header of each free block, which contains a pointer to the next free
    /// block of the same size.
    const Block = struct {
        next: ?*Block,
    };

    /// The block sizes. There will be a linked list of blocks of each size.
    /// These sizes must be ordered.
    const BLOCK_SIZES = [_]usize{ 8, 16, 32, 64, 128, 256, 512, 1024, 2048 };
    comptime {
        assert(std.sort.isSorted(usize, &BLOCK_SIZES, {}, std.sort.asc(usize)));
    }

    pub fn init() BlockAllocator {
        return BlockAllocator{
            .list_heads = [_]?*Block{null} ** BLOCK_SIZES.len,
        };
    }

    pub fn allocator(self: *BlockAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn getListIndex(size: usize) ?usize {
        for (BLOCK_SIZES, 0..) |block_size, i| {
            if (block_size >= size) return i;
        }
        return null;
    }

    fn sliceToBlock(slice: []u8) *Block {
        return @ptrCast(@alignCast(slice));
    }

    fn moreBlocksForList(self: *BlockAllocator, list_index: usize) !void {
        const page = try page_allocator.alloc(u8, std.mem.page_size);
        const block_len = BLOCK_SIZES[list_index];
        var block_addr = @intFromPtr(page.ptr);
        const page_end = block_addr + std.mem.page_size;
        while (block_addr < page_end - block_len) : (block_addr += block_len) {
            const block_ptr: *Block = @ptrFromInt(block_addr);
            const next_ptr: *Block = @ptrFromInt(block_addr + block_len);
            block_ptr.next = next_ptr;
        }
        const last_block: *Block = @ptrFromInt(block_addr);
        last_block.next = null;
        self.list_heads[list_index] = sliceToBlock(page);
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        log2_ptr_align: u8,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *BlockAllocator = @ptrCast(@alignCast(ctx));

        // Get list index corresponding to `len`, or fallback to page allocator
        // if there isn't any
        const list_index = getListIndex(len) orelse {
            return page_allocator.vtable.alloc(page_allocator.ptr, len, log2_ptr_align, ret_addr);
        };

        // Allocate blocks for the list if there isn't any
        if (self.list_heads[list_index] == null)
            self.moreBlocksForList(list_index) catch return null;

        // Get the head, and set the next block as the new head
        const block_ptr = self.list_heads[list_index].?;
        self.list_heads[list_index] = block_ptr.next;

        // Make sure the alignment is right
        assert(std.mem.isAlignedLog2(@intFromPtr(block_ptr), log2_ptr_align));

        // Return the block
        const ret: [*]u8 = @ptrCast(block_ptr);
        log.debug("heap allocator: {} returns {*}\n", .{ len, ret });
        return ret;
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ctx;
        _ = buf;
        _ = log2_buf_align;
        _ = new_len;
        _ = ret_addr;
        TODO();
    }

    fn free(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        ret_addr: usize,
    ) void {
        const self: *BlockAllocator = @ptrCast(@alignCast(ctx));
        const list_index = getListIndex(buf.len) orelse {
            return page_allocator.vtable.free(page_allocator.ptr, buf, log2_buf_align, ret_addr);
        };
        const freed_block = sliceToBlock(buf);
        freed_block.next = self.list_heads[list_index];
        self.list_heads[list_index] = freed_block;
        log.debug("heap allocator: frees {*}\n", .{buf});
    }
};

const PageAllocator = struct {
    const vtable = Allocator.VTable{
        .alloc = alloc,
        .free = free,
        .resize = resize,
    };

    fn alloc(
        _: *anyopaque,
        len: usize,
        log2_ptr_align: u8,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ret_addr;
        _ = log2_ptr_align;
        assert(len > 0);
        log.debug("page allocator alloc: {}\n", .{len});

        // The pages we're going to allocate
        const num_pages = @divExact(mem.alignPageForward(len), std.mem.page_size);

        // Allocate the pages and return them
        const range_start = mem.vmm.allocPages(num_pages, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        }) catch return null;
        log.debug("page allocator alloc return: 0x{x}\n", .{range_start});
        return @ptrFromInt(range_start);
    }

    fn free(_: *anyopaque, buf: []u8, log2_buf_align: u8, ret_addr: usize) void {
        _ = log2_buf_align;
        _ = ret_addr;

        // Free pages associated to `buf`.
        log.debug("page allocator free: {*}\n", .{buf});
        const buf_len_aligned = mem.alignPageForward(buf.len);
        const num_pages = @divExact(buf_len_aligned, std.mem.page_size);
        mem.vmm.freePages(@intFromPtr(buf.ptr), num_pages) catch |err| switch (err) {
            error.NotMapped => unreachable,
        };
    }

    fn resize(
        _: *anyopaque,
        buf: []u8,
        log2_buf_align: u8,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = log2_buf_align;
        _ = ret_addr;

        // Same as in std.heap.PageAllocator.resize().
        log.debug("page allocator resize: {*} {}\n", .{ buf, new_len });
        assert(mem.isPageAligned(@intFromPtr(buf.ptr)));
        const new_len_aligned = mem.alignPageForward(new_len);
        const buf_len_aligned = mem.alignPageForward(buf.len);

        // No need to do anything here.
        if (new_len_aligned == buf_len_aligned)
            return true;

        // Free pages.
        if (new_len_aligned < buf_len_aligned) {
            const base = @intFromPtr(buf.ptr) + new_len_aligned;
            const num_pages = @divExact(buf_len_aligned - new_len_aligned, std.mem.page_size);
            mem.vmm.freePages(base, num_pages) catch |err| switch (err) {
                error.NotMapped => unreachable,
            };
            return true;
        }

        // It's asking for an increase in size.
        return false;
    }
};
