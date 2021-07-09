usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const heap = @import("heap.zig");
const vmm = @import("vmm.zig");
const log = std.log.scoped(.pmm);

/// Virtual address of the physmap (a virtual mapping of all the physical memory).
var physmap_vaddr: usize = 0;

/// Bitset of free frames.
var free_bitset = std.StaticBitSet(bitset_size).initFull();

// This allows for 4096*8 pages, which is 128MB of memory
const bitset_size_bytes = std.mem.page_size;
const bitset_size = bitset_size_bytes * std.mem.byte_size_in_bits;

// The index of the frame after the last frame available.
var limit_frame_i: usize = undefined;

// Some wrappers around the bitset
fn isFree(i: usize) bool {
    return free_bitset.isSet(i);
}

fn setFree(i: usize) void {
    assert(i < free_bitset.capacity());
    free_bitset.set(i);
}

fn setAllocated(i: usize) void {
    assert(i < free_bitset.capacity());
    free_bitset.unset(i);
}

fn findFirstFree() ?usize {
    const i = free_bitset.findFirstSet() orelse return null;
    return if (i < limit_frame_i) i else null;
}

pub fn init() void {
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);
    physmap_vaddr = info.physmap_vaddr;

    // Set every frame from frame 0 to the one corresponding to info.mem_start
    // as not free.
    assert(x86.paging.isPageAligned(info.mem_start));
    const i_mem_start = info.mem_start / std.mem.page_size;
    var i: usize = 0;
    while (i < i_mem_start) : (i += 1) {
        setAllocated(i);
    }

    // Check the bitset is big enough for the physical memory we have
    assert(info.mem_length < bitset_size * std.mem.page_size);

    // Set the index corresponding to the limit of our physical memory according
    // to the hypervisor.
    assert(x86.paging.isPageAligned(info.mem_length));
    limit_frame_i = info.mem_length / std.mem.page_size;

    log.debug("PMM initialized\n", .{});
}

pub fn memoryLength() usize {
    return limit_frame_i * std.mem.page_size;
}

pub const Error = error{OutOfMemory};

pub fn allocFrame() Error!usize {
    const i = findFirstFree() orelse return Error.OutOfMemory;
    setAllocated(i);
    const frame = i * std.mem.page_size;
    log.debug("allocated frame: 0x{x}\n", .{frame});
    return frame;
}

// pub fn allocFrames(n: usize)

pub fn freeFrame(frame: usize) void {
    log.debug("freeing frame: 0x{x}\n", .{frame});
    defer log.debug("freed frame: 0x{x}\n", .{frame});
    assert(x86.paging.isPageAligned(frame));
    const i = frame / std.mem.page_size;
    assert(!isFree(i));
    setFree(i);
}

pub fn physToVirt(comptime ptr_type: type, phys: usize) ptr_type {
    assert(physmap_vaddr != 0);
    const ret = physmap_vaddr + phys;
    if (@typeInfo(ptr_type) == .Pointer) {
        return @intToPtr(ptr_type, ret);
    } else if (@typeInfo(ptr_type) == .Int) {
        return ret;
    } else {
        @compileError("ptr_type must be a pointer or an integer");
    }
}

pub fn virtToPhys(comptime ptr_type: type, virt: ptr_type) usize {
    assert(@typeInfo(ptr_type) == .Pointer);
    const virt_flat = @ptrToInt(virt);
    assert(physmap_vaddr <= virt_flat and virt_flat < physmap_vaddr + memory_length);
    return virt_flat - physmap_vaddr;
}

pub fn amountFreeFrames() usize {
    // We have to substract the part of the bitset we're not using
    return free_bitset.count() - (free_bitset.capacity() - limit_frame_i);
}

pub fn amountFreeMemory() usize {
    return amountFreeFrames() * std.mem.page_size;
}
