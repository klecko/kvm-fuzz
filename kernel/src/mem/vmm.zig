const std = @import("std");
const assert = std.debug.assert;
const mem = @import("mem.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const log = std.log.scoped(.vmm);
const Allocator = std.mem.Allocator;

/// The kernel page table.
pub var kernel_page_table: x86.paging.KernelPageTable = undefined;

/// Start of the allocations regions. Set to kernel brk at init().
var allocations_base_addr: usize = 0;

/// Bitset indicating if a page is free or not.
var free_bitset = std.StaticBitSet(bitset_size).initFull();

/// Each page of bitset allows for 4096*8 pages of virtual memory, which is 128MB.
const bitset_size_bytes = std.mem.page_size * 2;
const bitset_size = bitset_size_bytes * std.mem.byte_size_in_bits;
const max_memory = bitset_size * std.mem.page_size;

pub fn init() void {
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);
    if (info.mem_length > max_memory)
        std.debug.panic("max memory surpassed: {}M, but max is {}M", .{
            info.mem_length / (1024 * 1024),
            max_memory / (1024 * 1024),
        });

    // Initialize the kernel page table
    kernel_page_table = x86.paging.KernelPageTable.init();

    // Initialize the VMM
    mem.layout.kernel_brk = hypercalls.getKernelBrk();
    std.log.debug("kernel brk: {x}\n", .{mem.layout.kernel_brk});
    allocations_base_addr = mem.layout.kernel_brk;

    log.debug("VMM initialized\n", .{});
}

fn addrToPageIndex(addr: usize) usize {
    assert(mem.isPageAligned(addr));
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

const AllocPageError = mem.pmm.Error;
const MappingOptions = x86.paging.PageTable.MappingOptions;

/// Allocate a number of kernel pages, mapping them with given options.
pub fn allocPages(n: usize, options: MappingOptions) AllocPageError!usize {
    log.debug("allocPages: {}\n", .{n});
    assert(allocations_base_addr != 0);
    assert(!options.discardAlreadyMapped);
    assert(n > 0);

    // Check if we have enough memory available. Even if we have now, we may
    // fail later, but this check should almost always avoid that.
    if (mem.pmm.amountFreeFrames() < n)
        return AllocPageError.OutOfMemory;

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
        kernel_page_table.mapPage(page_base, frame, options) catch |err| switch (err) {
            error.OutOfMemory => return AllocPageError.OutOfMemory,
            error.AlreadyMapped => unreachable,
        };
    }

    log.debug("allocPages: returns 0x{x}\n", .{range_start});
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
    log.debug("freePages: freeing 0x{x} {}\n", .{ addr, n });
    defer log.debug("freePages: freed 0x{x} {}\n", .{ addr, n });
    assert(allocations_base_addr != 0);
    assert(mem.safe.isRangeInKernelRange(addr, n * std.mem.page_size));
    assert(mem.isPageAligned(addr));

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
