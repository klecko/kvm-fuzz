const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const scheduler = @import("../../scheduler.zig");
const cast = std.zig.c_translation.cast;
const mem = @import("../../mem/mem.zig");
const UserSlice = mem.safe.UserSlice;

fn sys_sched_getaffinity(
    self: *Process,
    pid: linux.pid_t,
    mask_ptr: UserSlice([]u8),
) !usize {
    std.debug.assert(pid == 0 or pid == self.pid);
    const mask = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0 };
    const size = @sizeOf(@TypeOf(mask));
    if (mask_ptr.len() < size)
        return error.InvalidArgument;

    try mem.safe.copyToUser(u8, mask_ptr.sliceTo(size), &mask);
    return @sizeOf(@TypeOf(mask)); // number of bytes written
}

pub fn handle_sys_sched_getaffinity(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
) !usize {
    const pid = cast(linux.pid_t, arg0);
    const mask_ptr = try UserSlice([]u8).fromFlat(arg2, arg1);
    return sys_sched_getaffinity(self, pid, mask_ptr);
}

pub fn handle_sys_sched_yield(self: *Process, regs: *Process.UserRegs) usize {
    _ = self;
    scheduler.schedule(regs);
    return regs.rax; // we have switched: don't overwrite rax
}
