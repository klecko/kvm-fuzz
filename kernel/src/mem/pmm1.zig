//! This PMM uses a static bitset to indicate if a frame is free or not. It does
//! not use dynamic memory, so the size for the bitset is fixed at comptime.
//! This limits the amount of memory the virtual machine can have.
//! It doesn't depend on the VMM. Free and alloc are both O(N).

usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const heap = @import("heap.zig");
const mem = @import("mem.zig");
const log = std.log.scoped(.pmm);

/// Bitset of free frames.
var free_bitset = std.StaticBitSet(bitset_size).initFull();

// This allows for 4096*8 pages, which is 128MB of memory. Same as in VMM.
const bitset_size_bytes = std.mem.page_size;
const bitset_size = bitset_size_bytes * std.mem.byte_size_in_bits;

// The index of the frame after the last frame available.
var limit_frame_i: usize = undefined;

var number_of_allocations: usize = 0;

// Some wrappers around the bitset
fn isFree(i: usize) bool {
    return free_bitset.isSet(i);
}

fn setFree(i: usize) void {
    assert(i < free_bitset.capacity());
    assert(!free_bitset.isSet(i));
    free_bitset.set(i);
}

fn setAllocated(i: usize) void {
    assert(i < free_bitset.capacity());
    assert(free_bitset.isSet(i));
    free_bitset.unset(i);
}

fn findFirstFree() ?usize {
    const i = free_bitset.findFirstSet() orelse return null;
    return if (i < limit_frame_i) i else null;
}

pub fn init() void {
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);

    // TODO: remove physmap_vaddr from meminfo
    assert(info.physmap_vaddr == mem.layout.physmap);

    // Set every frame from frame 0 to the one corresponding to info.mem_start
    // as not free.
    assert(mem.isPageAligned(info.mem_start));
    const i_mem_start = info.mem_start / std.mem.page_size;
    var i: usize = 0;
    while (i < i_mem_start) : (i += 1) {
        setAllocated(i);
    }

    // Check the bitset is big enough for the physical memory we have
    assert(info.mem_length < bitset_size * std.mem.page_size);

    // Set the index corresponding to the limit of our physical memory according
    // to the hypervisor.
    assert(mem.isPageAligned(info.mem_length));
    limit_frame_i = info.mem_length / std.mem.page_size;

    log.debug("PMM initialized\n", .{});
}

pub fn memoryLength() usize {
    return limit_frame_i * std.mem.page_size;
}

pub const Error = error{OutOfMemory};

/// Allocate a frame of physical memory. The contents of the frame are guaranteed
/// to be zero.
pub fn allocFrame() Error!usize {
    const i = findFirstFree() orelse return Error.OutOfMemory;
    setAllocated(i);
    const frame = i * std.mem.page_size;
    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), 0);
    log.debug("allocated frame: 0x{x}\n", .{frame});
    number_of_allocations += 1;
    return frame;
}

/// Allocate a number of frames. Returns a slice allocated with given allocator.
/// Caller is is charge of freeing it.
pub fn allocFrames(allocator: *std.mem.Allocator, n: usize) Error![]usize {
    // TODO: try these changes
    //   - Instead of calling allocFrame() each time, keep the index in the bitset
    //     while we iterate it
    //   - Maybe make sure n < amountFreeFrames() before doing anything else, so
    //     we can not fail in the loop
    var frames = try allocator.alloc(usize, n);
    var i: usize = 0;
    errdefer {
        freeFrames(frames[0..i]);
        allocator.free(frames);
    }
    while (i < n) : (i += 1) {
        frames[i] = try allocFrame();
    }
    return frames;
}

/// Free a frame of physical memory.
pub fn freeFrame(frame: usize) void {
    // Freed frame is set to undefined, to catch possible UAF in debug mode.
    assert(mem.isPageAligned(frame));
    const i = frame / std.mem.page_size;
    setFree(i);
    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), undefined);
    log.debug("freed frame: 0x{x}\n", .{frame});
}

/// Free a number of frames.
pub fn freeFrames(frames: []usize) void {
    for (frames) |frame| {
        freeFrame(frame);
    }
}

/// Convert a physical memory address to a virtual one. The returned virtual
/// address will be in the physmap region, a virtual mapping of all the physical
/// memory, and it will be casted to the given ptr_type.
pub fn physToVirt(comptime ptr_type: type, phys: usize) ptr_type {
    const ret = mem.layout.physmap + phys;
    if (@typeInfo(ptr_type) == .Pointer) {
        return @intToPtr(ptr_type, ret);
    } else if (@typeInfo(ptr_type) == .Int) {
        return ret;
    } else {
        @compileError("ptr_type must be a pointer or an integer");
    }
}

/// Convert a virtual memory address that belongs to the physmap region to a
/// physical one.
pub fn virtToPhys(virt: anytype) usize {
    assert(@typeInfo(@TypeOf(virt)) == .Pointer);
    const virt_flat = @ptrToInt(virt);
    const physmap = mem.layout.physmap;
    assert(physmap <= virt_flat and virt_flat < physmap + memoryLength());
    return virt_flat - physmap;
}

pub fn amountFreeFrames() usize {
    // We have to substract the part of the bitset we're not using
    return free_bitset.count() - (free_bitset.capacity() - limit_frame_i);
}

pub fn amountFreeMemory() usize {
    return amountFreeFrames() * std.mem.page_size;
}

pub fn numberOfAllocations() usize {
    return number_of_allocations;
}
