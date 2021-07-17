//! This PMM is a translation of the one in the C++ kernel. It holds the address
//! of the frame for the next allocation, and an ArrayList of freed frames for
//! reusing. It depends on the VMM for freeing, because the ArrayList uses
//! dynamic memory. Alloc is O(1), and free is O(1) when there isn't a
//! reallocation.
//! It has some problems when there's OOM: a page is unmapped and its frame is
//! freed as a result of an errdefer, then the ArrayList of freed frames needs
//! reallocation and the VMM handles it the same page that is being freed, and
//! then everyone dies. Or something like that.

usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("../x86/x86.zig");
const mem = @import("mem.zig");
const log = std.log.scoped(.pmm);

var next_frame_alloc: usize = 0;

var memory_length: usize = 0;

var free_frames: std.ArrayList(usize) = undefined;

var number_of_allocations: usize = 0;

pub fn init() void {
    var info: hypercalls.MemInfo = undefined;
    hypercalls.getMemInfo(&info);

    // TODO: remove physmap_vaddr from meminfo
    assert(info.physmap_vaddr == mem.layout.physmap);

    next_frame_alloc = info.mem_start;
    memory_length = info.mem_length;
    free_frames = std.ArrayList(usize).init(mem.heap.page_allocator);

    log.debug("PMM initialized\n", .{});
}

pub fn memoryLength() usize {
    return limit_frame_i * std.mem.page_size;
}

pub const Error = error{OutOfMemory};

/// Allocate a frame of physical memory. The contents of the frame are guaranteed
/// to be zero.
pub fn allocFrame() Error!usize {
    assert(next_frame_alloc != 0);

    var frame: usize = undefined;

    if (free_frames.items.len > 0) {
        frame = free_frames.pop();
    } else {
        if (next_frame_alloc > memory_length - std.mem.page_size)
            return Error.OutOfMemory;
        frame = next_frame_alloc;
        next_frame_alloc += std.mem.page_size;
    }

    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), 0);
    number_of_allocations += 1;
    log.debug("allocated frame: 0x{x}\n", .{frame});
    return frame;
}

/// Allocate a number of frames. Returns a slice allocated with given allocator.
/// Caller is is charge of freeing it.
pub fn allocFrames(allocator: *std.mem.Allocator, n: usize) Error![]usize {
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
pub noinline fn freeFrame(frame: usize) void {
    // Freed frame is set to undefined, to catch possible UAF in debug mode.
    assert(mem.isPageAligned(frame));
    std.mem.set(u8, physToVirt(*[std.mem.page_size]u8, frame), undefined);
    free_frames.append(frame) catch unreachable;
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
    const reused_frames = free_frames.items.len;
    const new_frames = @divExact(memory_length - next_frame_alloc, std.mem.page_size);
    return reused_frames + new_frames;
}

pub fn amountFreeMemory() usize {
    return amountFreeFrames() * std.mem.page_size;
}

pub fn numberOfAllocations() usize {
    return number_of_allocations;
}
