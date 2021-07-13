usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const mem = @import("mem.zig");
const log = std.log.scoped(.pmm);

var memory_length: usize = 0;

var free_frames: []usize = undefined;
var free_frames_len: usize = 0;

var number_of_allocations: usize = 0;

pub fn init() void {
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);

    // TODO: remove physmap_vaddr from meminfo
    assert(info.physmap_vaddr == mem.layout.physmap);

    var frames_availables = @divExact(info.mem_length - info.mem_start, std.mem.page_size);

    // Reserve some space for free_frames
    const space_needed_aligned = mem.alignPageForward(frames_availables * @sizeOf(usize));
    const frames_needed = @divExact(space_needed_aligned, std.mem.page_size);
    frames_availables -= frames_needed;
    free_frames = physToVirt([*]usize, info.mem_start)[0..frames_availables];
    info.mem_start += space_needed_aligned;

    var frame_base = info.mem_length - std.mem.page_size;
    for (free_frames) |*frame| {
        frame.* = frame_base;
        frame_base -= std.mem.page_size;
    }
    assert(free_frames[free_frames.len - 1] == info.mem_start);
    free_frames_len = frames_availables;

    memory_length = info.mem_length;

    log.debug("PMM initialized\n", .{});
}

pub fn memoryLength() usize {
    return limit_frame_i * std.mem.page_size;
}

pub const Error = error{OutOfMemory};

/// Allocate a frame of physical memory. The contents of the frame are guaranteed
/// to be zero.
pub noinline fn allocFrame() Error!usize {
    if (free_frames_len == 0)
        return Error.OutOfMemory;

    free_frames_len -= 1;
    const frame = free_frames[free_frames_len];
    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), 0);
    log.debug("allocated frame: 0x{x}\n", .{frame});
    number_of_allocations += 1;
    return frame;
}

/// Allocate a number of frames. Returns a slice allocated with given allocator.
/// Caller is is charge of freeing it.
pub fn allocFrames(allocator: *std.mem.Allocator, n: usize) Error![]usize {
    if (n > free_frames_len)
        return Error.OutOfMemory;

    var frames = try allocator.alloc(usize, n);
    free_frames_len -= n;
    std.mem.copy(usize, frames, free_frames[free_frames_len .. free_frames_len + n]);
    for (frames) |frame| {
        std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), 0);
    }
    number_of_allocations += n;
    return frames;
}

/// Free a frame of physical memory.
pub noinline fn freeFrame(frame: usize) void {
    // Freed frame is set to undefined, to catch possible UAF in debug mode.
    assert(mem.isPageAligned(frame));
    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), undefined);
    free_frames[free_frames_len] = frame;
    free_frames_len += 1;
    log.debug("freed frame: 0x{x}\n", .{frame});
}

/// Free a number of frames.
pub fn freeFrames(frames: []usize) void {
    std.mem.copy(usize, free_frames[free_frames_len..], frames);
    free_frames_len += frames.len;
    // for (frames) |frame| {
    //     freeFrame(frame);
    // }
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
    return free_frames_len;
}

pub fn amountFreeMemory() usize {
    return amountFreeFrames() * std.mem.page_size;
}

pub fn numberOfAllocations() usize {
    return number_of_allocations;
}
