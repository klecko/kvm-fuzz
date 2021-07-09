usingnamespace @import("../common.zig");
const mem = @import("mem.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const log = std.log.scoped(.vmm);
const Allocator = std.mem.Allocator;

/// The kernel page table.
pub var kernel_page_table: x86.paging.KernelPageTable = undefined;

/// The kernel page allocator. It is just a wrapper around allocPages() and
/// freePages(). Because of that, it doesn't work until the VMM is initialized.
var page_allocator_state = PageAllocator.init();
pub const page_allocator = &page_allocator_state.allocator;

/// Start of the allocations regions. Set to kernel brk at init().
var allocations_base_addr: usize = 0;

/// Bitset indicating if a page is free or not.
var free_bitset = std.StaticBitSet(bitset_size).initFull();

/// This allows for 4096*8 pages, which is 128MB. Same as in PMM.
const bitset_size_bytes = std.mem.page_size;
const bitset_size = bitset_size_bytes * std.mem.byte_size_in_bits;

const PageAllocator = struct {
    allocator: Allocator,

    pub fn init() PageAllocator {
        return PageAllocator{
            .allocator = Allocator{
                .allocFn = alloc,
                .resizeFn = resize,
            },
        };
    }

    fn alloc(allocator: *Allocator, len: usize, ptr_align: u29, len_align: u29, ret_addr: usize) Allocator.Error![]u8 {
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

        // The length and pages we're going to allocate
        const page_aligned_len = std.mem.alignForward(len, std.mem.page_size);
        const num_pages = page_aligned_len / std.mem.page_size;

        // Alocate the pages. Getting an error other than OOM is a bug.
        const range_start = allocPages(num_pages, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        }) catch |err| switch (err) {
            error.OutOfMemory => return Allocator.Error.OutOfMemory,
            else => unreachable,
        };

        // Construct the slice and return it
        const range_start_ptr = @intToPtr([*]u8, range_start);
        const slice = range_start_ptr[0..len];
        log.debug("page allocator alloc return: {*}\n", .{slice.ptr});
        return slice;
    }

    fn resize(allocator: *Allocator, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, ret_addr: usize) Allocator.Error!usize {
        log.debug("page allocator resize: {*} {} {} {}\n", .{ buf, buf_align, new_len, len_align });
        if (new_len == 0) {
            // The length and pages we're going to free.
            const page_aligned_len = std.mem.alignForward(buf.len, std.mem.page_size);
            const num_pages = page_aligned_len / std.mem.page_size;

            // Free pages. Getting an error is a bug.
            freePages(@ptrToInt(buf.ptr), num_pages) catch unreachable;
            return 0;
        }
        print("TODO\n", .{});
        assert(false);
        return Allocator.Error.OutOfMemory;
    }
};

pub fn init() void {
    // Initialize the kernel page table
    kernel_page_table = x86.paging.KernelPageTable.init();

    // Initialize the VMM
    mem.layout.kernel_brk = hypercalls.getKernelBrk();
    std.log.debug("kernel brk: {x}\n", .{mem.layout.kernel_brk});
    allocations_base_addr = mem.layout.kernel_brk;

    log.debug("VMM initialized\n", .{});
}

fn addrToPageIndex(addr: usize) usize {
    assert(x86.paging.isPageAligned(addr));
    return (addr - allocations_base_addr) / std.mem.page_size;
}

fn setPageFree(i: usize) void {
    assert(i < free_bitset.capacity());
    assert(!free_bitset.isSet(i));
    free_bitset.set(i);
}

fn setPageAllocated(i: usize) void {
    assert(i < free_bitset.capacity());
    assert(free_bitset.isSet(i));
    free_bitset.unset(i);
}

fn isPageFree(i: usize) bool {
    assert(i <= free_bitset.capacity());
    return free_bitset.isSet(i);
}

const AllocPageError = x86.paging.PageTable.MappingError || mem.pmm.Error;
const MappingOptions = x86.paging.PageTable.MappingOptions;

/// Allocate a number of kernel pages, mapping them with given options.
pub fn allocPages(n: usize, options: MappingOptions) AllocPageError!usize {
    // log.debug("allogPages: alloc: {} {} {}\n", .{ len, ptr_align, len_align });
    assert(allocations_base_addr != 0);
    assert(!options.discardAlreadyMapped);
    assert(n > 0);

    // Find range of not allocated pages
    const i_range_start = findFreeRange(n) orelse return AllocPageError.OutOfMemory;
    const i_range_end = i_range_start + n;
    const range_start = allocations_base_addr + i_range_start * std.mem.page_size;

    // Iterate the range, allocating a frame for every page and mapping it.
    var i: usize = i_range_start;
    var page_base = range_start;
    var frame: usize = undefined;
    errdefer handleAllocError(i_range_start, i, frame);
    while (i < i_range_end) : ({
        i += 1;
        page_base += std.mem.page_size;
    }) {
        frame = try mem.pmm.allocFrame();
        setPageAllocated(i);
        try kernel_page_table.mapPage(page_base, frame, options);
    }

    // log.debug("page allocator alloc return: {*}\n", .{slice.ptr});
    return range_start;
}

fn handleAllocError(i_range_start: usize, i: usize, last_frame: usize) void {
    // We failed at iteration i, which means we completed iterations from
    // i_range_start to i - 1. We must free pages allocated in those iterations.
    const range_start = allocations_base_addr + i_range_start * std.mem.page_size;
    freePages(range_start, i - i_range_start) catch unreachable;

    // If we failed at mapPage(), we must also free the last frame allocated
    // in that iteration and mark that page as free.
    if (!isPageFree(i)) {
        mem.pmm.freeFrame(last_frame);
        setPageFree(i);
    }
}

pub fn allocPage(options: MappingOptions) AllocPageError!usize {
    return allocPages(1, options);
}

pub const FreePageError = x86.paging.PageTable.UnmappingError;

/// Free pages returned by allocPages(), unmapping them and freeing the
/// underlying memory.
pub fn freePages(addr: usize, n: usize) FreePageError!void {
    assert(allocations_base_addr != 0);
    assert(mem.safe.isRangeInKernelRange(addr, n * std.mem.page_size));
    assert(x86.paging.isPageAligned(addr));

    // Iterate the range, unmapping each page (and thus freeing each frame)
    // TODO: if unmapping is changed so it doesn't free anymore, change this
    const i_range_start = addrToPageIndex(addr);
    const i_range_end = i_range_start + n;
    var i: usize = i_range_start;
    var page_base = allocations_base_addr + i * std.mem.page_size;
    while (i < i_range_end) : ({
        i += 1;
        page_base += std.mem.page_size;
    }) {
        setPageFree(i);
        try kernel_page_table.unmapPage(page_base);
    }
}

pub fn freePage(addr: usize) FreePageError!void {
    return freePages(addr, 1);
}

/// Find a contiguous region of free memory of `num_pages`, and return
/// the index to the first page.
fn findFreeRange(num_pages: usize) ?usize {
    // Initialize the current range with the first ocurrence of a free page,
    // if there's any.
    var iter = free_bitset.iterator(.{});
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
