usingnamespace @import("../common.zig");
const mem = @import("mem.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const log = std.log.scoped(.vmm);
const Allocator = std.mem.Allocator;

/// The kernel page table.
pub var kernel_page_table: x86.paging.KernelPageTable = undefined;

/// Start of the allocations regions. Set to kernel brk at init().
var allocations_base_addr: usize = undefined;

var region_manager: mem.RegionManager = undefined;

pub fn init() void {
    // Initialize the kernel page table
    kernel_page_table = x86.paging.KernelPageTable.init();

    // Initialize the VMM
    mem.layout.kernel_brk = hypercalls.getKernelBrk();
    std.log.debug("kernel brk: {x}\n", .{mem.layout.kernel_brk});
    allocations_base_addr = mem.layout.kernel_brk;

    region_manager = mem.RegionManager.init(
        mem.heap.page_allocator,
        allocations_base_addr,
        mem.pmm.memoryLength(),
    );

    log.debug("VMM initialized\n", .{});
}

const AllocPageError = mem.pmm.Error;
const MappingOptions = x86.paging.PageTable.MappingOptions;

/// Allocate a number of kernel pages, mapping them with given options.
pub fn allocPages(n: usize, options: MappingOptions) AllocPageError!usize {
    log.debug("allocPages: {}\n", .{n});
    assert(allocations_base_addr != 0);
    assert(!options.discardAlreadyMapped);
    assert(n > 0);

    // Check if we have enough memory available. Even if we have now, we may
    // fail later, but this check should almost always avoid that. We can't use
    // mem.pmm.allocFrames(), as it requires an allocator.
    if (mem.pmm.amountFreeFrames() < n)
        return AllocPageError.OutOfMemory;

    // Find range of not allocated pages
    const range_length = n * std.mem.page_size;
    const range_start = region_manager.findNotMapped(range_length) orelse return AllocPageError.OutOfMemory;
    const range_end = range_start + range_length;

    // Mark range as mapped. TODO: think about what happens if this tries to allocate
    try region_manager.setMapped(range_start, range_end);

    // Iterate the range, allocating a frame for every page and mapping it.
    var page_base = range_start;
    var frame: usize = undefined;
    errdefer {
        // Free pages allocated
        const pages_allocated = @divExact(page_base - range_start, std.mem.page_size);
        freePages(range_start, pages_allocated) catch unreachable;

        // Set the rest of the region as not mapped too.
        region_manager.setNotMapped(page_base, range_end) catch unreachable;

        // TODO: `frame` is leaked if we fail at mapPage
    }
    while (page_base < range_end) : (page_base += std.mem.page_size) {
        frame = try mem.pmm.allocFrame();
        kernel_page_table.mapPage(page_base, frame, options) catch |err| switch (err) {
            error.OutOfMemory => return AllocPageError.OutOfMemory,
            error.AlreadyMapped => unreachable,
        };
    }

    log.debug("allocPages: returns 0x{x}\n", .{range_start});
    return range_start;
}

pub fn allocPage(options: MappingOptions) AllocPageError!usize {
    return allocPages(1, options);
}

pub const FreePageError = x86.paging.PageTable.UnmappingError || error{OutOfMemory};

/// Free pages returned by allocPages(), unmapping them and freeing the
/// underlying memory.
pub fn freePages(addr: usize, n: usize) FreePageError!void {
    log.debug("freePages: freeing 0x{x} {}\n", .{ addr, n });
    defer log.debug("freePages: freed 0x{x} {}\n", .{ addr, n });
    assert(allocations_base_addr != 0);
    assert(mem.safe.isRangeInKernelRange(addr, n * std.mem.page_size));
    assert(mem.isPageAligned(addr));

    // Iterate the range, unmapping each page (and thus freeing each frame)
    const range_length = n * std.mem.page_size;
    const range_end = addr + range_length;
    try region_manager.setNotMapped(addr, range_end);
    var page_base = addr;
    while (page_base < range_end) : (page_base += std.mem.page_size) {
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
