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
        return Allocator.init(self, alloc, resize, free);
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
        self: *HeapAllocator,
        len: usize,
        ptr_align: u29,
        len_align: u29,
        ret_addr: usize,
    ) Allocator.Error![]u8 {
        _ = len_align;
        _ = ret_addr;

        const ret_offset = std.mem.alignForward(self.used, ptr_align);
        const free_bytes = self.size - ret_offset;
        if (len > free_bytes) {
            const needed_memory = mem.alignPageForward(len - free_bytes);
            const num_pages = @divExact(needed_memory, std.mem.page_size);
            try self.more(num_pages);
        }

        self.used = ret_offset + len;
        assert(self.used <= self.size);
        const ret = self.base + ret_offset;
        log.debug("heap allocator: returns 0x{x}\n", .{ret});
        return @intToPtr([*]u8, ret)[0..len];
    }

    fn resize(
        self: *HeapAllocator,
        buf: []u8,
        buf_align: u29,
        new_len: usize,
        len_align: u29,
        ret_addr: usize,
    ) ?usize {
        _ = self;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = len_align;
        _ = ret_addr;
        TODO();
    }

    fn free(
        self: *HeapAllocator,
        buf: []u8,
        buf_align: u29,
        ret_addr: usize,
    ) void {
        _ = self;
        _ = buf_align;
        _ = ret_addr;
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

    pub fn init() BlockAllocator {
        return BlockAllocator{
            .list_heads = [_]?*Block{null} ** BLOCK_SIZES.len,
        };
    }

    pub fn allocator(self: *BlockAllocator) Allocator {
        return Allocator.init(self, alloc, resize, free);
    }

    fn getListIndex(size: usize) ?usize {
        for (BLOCK_SIZES) |block_size, i| {
            if (block_size >= size) return i;
        }
        return null;
    }

    fn blockToSlice(block_ptr: *Block, size: usize) []u8 {
        return @ptrCast([*]u8, block_ptr)[0..size];
    }

    fn sliceToBlock(slice: []u8) *Block {
        return @ptrCast(*Block, @alignCast(@sizeOf(Block), slice));
    }

    fn moreBlocksForList(self: *BlockAllocator, list_index: usize) !void {
        const page = try page_allocator.alloc(u8, std.mem.page_size);
        const block_len = BLOCK_SIZES[list_index];
        var block_addr = @ptrToInt(page.ptr);
        var page_end = block_addr + std.mem.page_size;
        while (block_addr < page_end - block_len) : (block_addr += block_len) {
            var block_ptr = @intToPtr(*Block, block_addr);
            const next_ptr = @intToPtr(*Block, block_addr + block_len);
            block_ptr.next = next_ptr;
        }
        var last_block = @intToPtr(*Block, block_addr);
        last_block.next = null;
        self.list_heads[list_index] = sliceToBlock(page);
    }

    fn alloc(
        self: *BlockAllocator,
        len: usize,
        ptr_align: u29,
        len_align: u29,
        ret_addr: usize,
    ) Allocator.Error![]u8 {
        // Get list index corresponding to `len`, or fallback to page allocator
        // if there isn't any
        const list_index = getListIndex(len) orelse {
            return page_allocator.vtable.alloc(page_allocator.ptr, len, ptr_align, len_align, ret_addr);
        };

        // Allocate blocks for the list if there isn't any
        if (self.list_heads[list_index] == null)
            try self.moreBlocksForList(list_index);

        // Get the head, and set the next block as the new head
        const block_ptr = self.list_heads[list_index].?;
        const next = block_ptr.next;
        self.list_heads[list_index] = next;

        // Return the slice with aligned length
        const block_len = BLOCK_SIZES[list_index];
        const len_aligned = std.mem.alignAllocLen(block_len, len, len_align);
        const ret = blockToSlice(block_ptr, len_aligned);
        log.debug("heap allocator: {} returns {*}\n", .{ len, ret });
        return ret;
    }

    fn resize(
        self: *BlockAllocator,
        buf: []u8,
        buf_align: u29,
        new_len: usize,
        len_align: u29,
        ret_addr: usize,
    ) ?usize {
        _ = self;
        _ = buf;
        _ = buf_align;
        _ = new_len;
        _ = len_align;
        _ = ret_addr;
        TODO();
    }

    fn free(
        self: *BlockAllocator,
        buf: []u8,
        buf_align: u29,
        ret_addr: usize,
    ) void {
        const list_index = getListIndex(buf.len) orelse {
            return page_allocator.vtable.free(page_allocator.ptr, buf, buf_align, ret_addr);
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
        ptr_align: u29,
        len_align: u29,
        ret_addr: usize,
    ) Allocator.Error![]u8 {
        _ = ret_addr;
        log.debug("page allocator alloc: {} {} {}\n", .{ len, ptr_align, len_align });

        // As we always return a page aligned pointer, with this constraint we
        // make sure it will be also aligned by ptr_align.
        assert(ptr_align <= std.mem.page_size);

        // Allocator constraints
        assert(len > 0);
        assert(std.mem.isValidAlign(ptr_align));
        if (len_align > 0) {
            assert(std.mem.isAlignedAnyAlign(len, len_align));
            assert(len >= len_align);
        }

        // The pages we're going to allocate
        const num_pages = @divExact(mem.alignPageForward(len), std.mem.page_size);

        // Alocate the pages
        const range_start = try mem.vmm.allocPages(num_pages, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        });

        // Construct the slice and return it
        const range_start_ptr = @intToPtr([*]u8, range_start);
        const slice = range_start_ptr[0..len];
        log.debug("page allocator alloc return: {*}\n", .{slice.ptr});
        return slice;
    }

    fn free(_: *anyopaque, buf: []u8, buf_align: u29, ret_addr: usize) void {
        _ = buf_align;
        _ = ret_addr;

        // Free pages associated to `buf`.
        log.debug("page allocator free: {*}\n", .{buf});
        const buf_len_aligned = mem.alignPageForward(buf.len);
        const num_pages = @divExact(buf_len_aligned, std.mem.page_size);
        mem.vmm.freePages(@ptrToInt(buf.ptr), num_pages) catch |err| switch (err) {
            error.NotMapped => unreachable,
        };
    }

    fn resize(
        _: *anyopaque,
        buf: []u8,
        buf_align: u29,
        new_len: usize,
        len_align: u29,
        ret_addr: usize,
    ) ?usize {
        _ = buf_align;
        _ = ret_addr;

        // Same as in std.heap.PageAllocator.resize
        log.debug("page allocator resize: {*} {} {}\n", .{ buf, new_len, len_align });
        assert(mem.isPageAligned(@ptrToInt(buf.ptr)));
        const new_len_aligned = mem.alignPageForward(new_len);
        const buf_len_aligned = mem.alignPageForward(buf.len);

        // No need to do anything here.
        if (new_len_aligned == buf_len_aligned)
            return std.heap.alignPageAllocLen(new_len_aligned, new_len, len_align);

        // Free pages.
        if (new_len_aligned < buf_len_aligned) {
            const base = @ptrToInt(buf.ptr) + new_len_aligned;
            const num_pages = @divExact(buf_len_aligned - new_len_aligned, std.mem.page_size);
            mem.vmm.freePages(base, num_pages) catch |err| switch (err) {
                error.NotMapped => unreachable,
            };
            return std.heap.alignPageAllocLen(new_len_aligned, new_len, len_align);
        }

        // It's asking for an increase in size.
        return null;
    }
};
