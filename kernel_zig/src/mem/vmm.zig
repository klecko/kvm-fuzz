usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const pmm = @import("pmm.zig");
const x86 = @import("../x86/x86.zig");
const log = std.log.scoped(.vmm);
const Allocator = std.mem.Allocator;

/// The kernel page table.
pub var kernel_page_table: x86.paging.KernelPageTable = undefined;

/// The kernel page allocator. The state is initialized at runtime in init().
var page_allocator_state = PageAllocator{};
pub const page_allocator = &page_allocator_state.allocator;

const PageAllocator = struct {
    allocator: Allocator = .{
        .allocFn = alloc,
        .resizeFn = resize,
    },

    /// Range of memory available for use. This memory is not mapped yet.
    range_addr: usize = undefined,
    // range_size: usize = undefined,

    // Bitset indicating if a page is mapped or not
    mapped_bitset: std.StaticBitSet(bitset_size) = undefined,

    // Bitset indicating if a page is free or not
    free_bitset: std.StaticBitSet(bitset_size) = undefined,

    // This allows for 4096*8 pages, which is 128MB
    const bitset_size_bytes = std.mem.page_size;
    const bitset_size = bitset_size_bytes * std.mem.byte_size_in_bits;

    pub fn init(base_addr: usize) PageAllocator {
        // Make sure the range is properly aligned
        assert(x86.paging.isPageAligned(base_addr));
        // assert(x86.paging.isPageAligned(@ptrToInt(range.ptr)));
        // assert(x86.paging.isPageAligned(range.len));

        // Make sure out bitset is big enough for given range
        // const num_pages = range.len / std.mem.page_size;
        // assert(bitset_size >= num_pages);

        return PageAllocator{
            .allocator = Allocator{
                .allocFn = alloc,
                .resizeFn = resize,
            },
            .range_addr = base_addr,
            // .range_addr = @ptrToInt(range.ptr),
            // .range_size = range.len,
            .mapped_bitset = std.StaticBitSet(bitset_size).initEmpty(),
            .free_bitset = std.StaticBitSet(bitset_size).initFull(),
        };
    }

    fn alloc(allocator: *Allocator, len: usize, ptr_align: u29, len_align: u29, ret_addr: usize) Allocator.Error![]u8 {
        log.debug("page allocator alloc: {} {} {}\n", .{ len, ptr_align, len_align });
        const self = @fieldParentPtr(PageAllocator, "allocator", allocator);

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

        // The length and pages we're going to allocate
        const page_aligned_len = std.mem.alignForward(len, std.mem.page_size);
        const num_pages = page_aligned_len / std.mem.page_size;

        // Find range of not allocated pages
        const i_range_start = self.findFreeRange(num_pages) orelse return Error.OutOfMemory;
        const i_range_end = i_range_start + num_pages;
        const range_start = self.range_addr + i_range_start * std.mem.page_size;

        // Iterate the range in both bitmaps, mapping every page that is not
        // already mapped and setting every page as allocated.
        var i: usize = i_range_start;
        errdefer self.handleAllocationFailed(i_range_start, i);
        while (i < i_range_end) : (i += 1) {
            if (!self.mapped_bitset.isSet(i)) {
                const page_addr = self.range_addr + i * std.mem.page_size;
                try allocPage(page_addr);
                self.mapped_bitset.set(i);
            }
            self.setPageAllocated(i);
        }

        // Construct the slice and return it
        const range_start_ptr = @intToPtr([*]u8, range_start);
        const slice = range_start_ptr[0..len];
        log.debug("page allocator alloc return: {*}\n", .{slice.ptr});
        return slice;
    }

    fn handleAllocationFailed(self: *PageAllocator, i_start: usize, i_end: usize) void {
        // Attempting to allocate memory from a range starting at i_start
        // failed at i_end. We want to mark those pages as free, because we
        // didn't succeed with the allocation, and also free some memory.
        // First, set every allocated page as free.
        var i: usize = i_start;
        while (i < i_end) : (i += 1) {
            self.setPageFree(i);
        }

        // We have set every allocated as free in the allocator, but they
        // are still mapped, so the physical memory has not actually been
        // freed and it still belongs to us. Iterate the whole bitmap and
        // free every page that is marked as free. We could just free the
        // pages we set as free in the previous loop, but we free every
        // possible page to attempt to avoid OOM in the near future.
        i = 0;
        while (i < self.mapped_bitset.capacity()) : (i += 1) {
            if (self.mapped_bitset.isSet(i) and self.free_bitset.isSet(i)) {
                const addr = self.range_addr + i * std.mem.page_size;
                freePage(addr) catch unreachable;
                self.mapped_bitset.unset(i);
            }
        }
    }

    fn resize(allocator: *Allocator, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, ret_addr: usize) Allocator.Error!usize {
        const self = @fieldParentPtr(PageAllocator, "allocator", allocator);

        // print("page allocator resize: {*} {} {} {}\n", .{ buf, buf_align, new_len, len_align });
        // assert(self.ownsSlice(buf));
        const page_aligned_len = std.mem.alignForward(buf.len, std.mem.page_size);
        const num_pages = page_aligned_len / std.mem.page_size;

        if (new_len == 0) {
            // Mark every page of the buffer as free
            const i_range_start = self.ptrToPageIndex(buf.ptr);
            var i: usize = i_range_start;
            while (i < i_range_start + num_pages) : (i += 1) {
                self.setPageFree(i);
            }
            return 0;
        }
        print("TODO\n", .{});
        assert(false);
        return Allocator.Error.OutOfMemory;
    }

    fn setPageFree(self: *PageAllocator, i: usize) void {
        assert(i <= self.free_bitset.capacity());
        assert(!self.free_bitset.isSet(i));
        self.free_bitset.set(i);
        // print("marked page as free: {}\n", .{i});
    }

    fn setPageAllocated(self: *PageAllocator, i: usize) void {
        assert(i <= self.free_bitset.capacity());
        assert(self.free_bitset.isSet(i));
        self.free_bitset.unset(i);
        // print("marked page as allocated: {}\n", .{i});
    }

    // fn ownsSlice(self: *PageAllocator, slice: []u8) bool {
    //     const slice_addr = @ptrToInt(slice.ptr);
    //     return (self.range_addr <= slice_addr) and
    //         (slice_addr + slice.len <= self.range_addr + self.range_size);
    // }

    fn ptrToPageIndex(self: *PageAllocator, ptr: [*]u8) usize {
        const addr = @ptrToInt(ptr);
        assert(std.mem.isAligned(addr, std.mem.page_size));
        return (addr - self.range_addr) / std.mem.page_size;
    }

    /// Find a contiguous region of free memory of `num_pages`, and return
    /// the index to the first page.
    fn findFreeRange(self: *PageAllocator, num_pages: usize) ?usize {
        // Initialize the current range with the first ocurrence of a free page,
        // if there's any.
        var iter = self.free_bitset.iterator(.{});
        var current_range_i: usize = iter.next() orelse return null;
        var current_range_size: usize = 1;
        var prev_i: usize = current_range_i;

        // If we're looking for just one page, we already have it.
        if (num_pages == 1)
            return current_range_i;

        // Iterate the bitmap until we find a large enough range of contiguous
        // free pages.
        while (iter.next()) |i| {
            if (i == prev_i + 1) {
                current_range_size += 1;
            } else {
                current_range_i = i;
                current_range_size = 1;
            }
            if (current_range_size == num_pages)
                return current_range_i;
            prev_i = i;
        }
        return null;
    }
};

pub fn init() void {
    // Initialize the kernel page table
    kernel_page_table = x86.paging.KernelPageTable.init();

    // Initialize the page allocator
    const kernel_brk = hypercalls.getKernelBrk();
    log.debug("kernel brk: {x}\n", .{kernel_brk});
    page_allocator_state = PageAllocator.init(kernel_brk);

    log.debug("VMM initialized\n", .{});
}

pub const Error = error{OutOfMemory};

pub fn allocPage(addr: usize) Error!void {
    return allocPages(addr, 1);
}

pub fn allocPages(addr: usize, n: usize) Error!void {
    assert(x86.paging.isPageAligned(addr));
    var i: usize = 0;
    var page_base = addr;
    while (i < n) : ({
        i += 1;
        page_base += x86.paging.PAGE_SIZE;
    }) {
        // TODO: page already mapped?
        const frame = try pmm.allocFrame();
        try kernel_page_table.mapPage(page_base, frame, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        });
    }
}

pub fn freePage(addr: usize) !void {
    return freePages(addr, 1);
}

pub fn freePages(addr: usize, n: usize) !void {
    assert(x86.paging.isPageAligned(addr));
    var i: usize = 0;
    var page_base = addr;
    while (i < n) : ({
        i += 1;
        page_base += x86.paging.PAGE_SIZE;
    }) {
        // TODO: not mapped?
        try kernel_page_table.unmapPage(page_base);
    }
}
