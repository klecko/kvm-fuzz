usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const log = std.log.scoped(.pmm);

var physmap_vaddr: usize = 0;
var next_frame_alloc: usize = 0;
var memory_length: usize = 0;
var free_frames: std.ArrayList(usize) = undefined;

pub fn init() void {
    assert(next_frame_alloc == 0);
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);
    physmap_vaddr = info.physmap_vaddr;
    next_frame_alloc = info.mem_start;
    memory_length = info.mem_length;
    log.debug("PMM initialized\n", .{});
}

pub fn memoryLength() usize {
    return memory_length;
}

pub fn allocFrame() !usize {
    assert(next_frame_alloc != 0);

    // Check if there's a free frame we can return

    // We need to allocate a new frame. First, check if we are OOM.
    if (next_frame_alloc > memory_length - x86.paging.PAGE_SIZE)
        return error.OutOfMemory;

    // Allocate frame
    const frame = next_frame_alloc;
    next_frame_alloc += x86.paging.PAGE_SIZE;
    return frame;
}

// pub fn allocFrames(n: usize)

pub fn freeFrame(frame: usize) void {}

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
