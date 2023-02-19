//! This PMM has a slice of free frames, which contains every single free frame.
//! The memory for this slice is allocated at `init()` depending on the memory
//! length, and it does not depend on the VMM. Both free and alloc are O(1).

const std = @import("std");
const assert = std.debug.assert;
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const mem = @import("mem.zig");
const log = std.log.scoped(.pmm);

var memory_length: usize = 0;

var free_frames: []usize = undefined;
var free_frames_len: usize = 0;

const BITSET_CHECKS = std.debug.runtime_safety;
var free_bitset: []u8 = undefined;

var number_of_allocations: usize = 0;

pub fn init() void {
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);

    // TODO: remove physmap_vaddr from meminfo
    assert(info.physmap_vaddr == mem.layout.physmap);
    memory_length = info.mem_length;

    var frames_availables = @divExact(info.mem_length - info.mem_start, std.mem.page_size);

    // Reserve space for free_frames
    const space_needed_free_frames = mem.alignPageForward(frames_availables * @sizeOf(usize));
    const frames_needed_free_frames = @divExact(space_needed_free_frames, std.mem.page_size);
    frames_availables -= frames_needed_free_frames;
    const free_frames_start = info.mem_start;
    info.mem_start += space_needed_free_frames;

    if (BITSET_CHECKS) {
        // Reserve space for the bitset
        const space_needed_bitset = mem.alignPageForward(std.math.divCeil(usize, frames_availables, 8) catch unreachable);
        free_bitset = physToVirt([*]u8, info.mem_start)[0..space_needed_bitset];
        const frames_needed_bitset = @divExact(space_needed_bitset, std.mem.page_size);
        frames_availables -= frames_needed_bitset;
        info.mem_start += space_needed_bitset;

        // Initialize the bitset
        std.mem.set(u8, free_bitset, 0xFF); // all free
        var frame: usize = 0;
        while (frame < info.mem_start) : (frame += std.mem.page_size) {
            setFrameAllocated(frame);
        }
    }

    free_frames = physToVirt([*]usize, free_frames_start)[0..frames_availables];

    // Populate free_frames
    var frame_base = info.mem_length - std.mem.page_size;
    for (free_frames) |*frame| {
        frame.* = frame_base;
        frame_base -= std.mem.page_size;
    }
    assert(free_frames[free_frames.len - 1] == info.mem_start);
    free_frames_len = frames_availables;

    log.debug("PMM initialized\n", .{});
}

fn setFrameAllocated(frame: usize) void {
    const i = @divExact(frame, std.mem.page_size);
    const byte = i / 8;
    const bit = @as(u8, 1) << @intCast(u3, i % 8);
    assert(free_bitset[byte] & bit != 0);
    free_bitset[byte] &= ~bit;
}

fn setFrameFree(frame: usize) void {
    const i = @divExact(frame, std.mem.page_size);
    const byte = i / 8;
    const bit = @as(u8, 1) << @intCast(u3, i % 8);
    assert(free_bitset[byte] & bit == 0);
    free_bitset[byte] |= bit;
}

fn memsetFrame(frame: usize, value: u8) void {
    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), value);
}

pub fn memoryLength() usize {
    return memory_length;
}

pub const Error = error{OutOfMemory};

/// Allocate a frame of physical memory. The contents of the frame are guaranteed
/// to be zero.
pub noinline fn allocFrame() Error!usize {
    if (free_frames_len == 0)
        return Error.OutOfMemory;

    free_frames_len -= 1;
    const frame = free_frames[free_frames_len];
    if (BITSET_CHECKS)
        setFrameAllocated(frame);
    memsetFrame(frame, 0);
    log.debug("allocated frame: 0x{x}\n", .{frame});
    // number_of_allocations += 1;
    return frame;
}

pub fn allocFrames(allocator: std.mem.Allocator, n: usize) Error![]usize {
    // It's important to allocate the slice first, because it may also need to
    // allocate frames
    var frames = try allocator.alloc(usize, n);
    errdefer allocator.free(frames);

    if (n > free_frames_len)
        return Error.OutOfMemory;
    free_frames_len -= n;
    std.mem.copy(usize, frames, free_frames[free_frames_len .. free_frames_len + n]);
    for (frames) |frame| {
        if (BITSET_CHECKS)
            setFrameAllocated(frame);
        memsetFrame(frame, 0);
    }
    // number_of_allocations += n;
    for (frames) |frame| {
        log.debug("allocated frame: 0x{x}\n", .{frame});
    }
    return frames;
}

/// Free a frame of physical memory.
pub fn freeFrame(frame: usize) void {
    // Freed frame is set to undefined, to catch possible UAF in debug mode.
    assert(mem.isPageAligned(frame));
    if (BITSET_CHECKS)
        setFrameFree(frame);
    memsetFrame(frame, undefined);
    free_frames[free_frames_len] = frame;
    free_frames_len += 1;
    log.debug("freed frame: 0x{x}\n", .{frame});
}

/// Free a number of frames.
pub fn freeFrames(frames: []usize) void {
    std.mem.copy(usize, free_frames[free_frames_len..], frames);
    for (frames) |frame| {
        if (BITSET_CHECKS)
            setFrameFree(frame);
        memsetFrame(frame, undefined);
    }
    free_frames_len += frames.len;
}

/// Convert a physical memory address to a virtual one. The returned virtual
/// address will be in the physmap region, a virtual mapping of all the physical
/// memory, and it will be casted to the given ptr_type.
pub fn physToVirt(comptime ptr_type: type, phys: usize) ptr_type {
    assert(phys <= memory_length);
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
    return free_frames_len;
}

pub fn amountFreeMemory() usize {
    return amountFreeFrames() * std.mem.page_size;
}

pub fn numberOfAllocations() usize {
    return number_of_allocations;
}

pub fn dupFrame(frame: usize) Error!usize {
    const new_frame = try allocFrame();
    const new_frame_virt = physToVirt(*[std.mem.page_size]u8, new_frame);
    const frame_virt = physToVirt(*[std.mem.page_size]u8, frame);
    std.mem.copy(u8, new_frame_virt, frame_virt);
    return new_frame;
}
