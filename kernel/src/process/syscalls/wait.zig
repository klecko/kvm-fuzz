const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const scheduler = @import("../../scheduler.zig");
const panic = @import("../../common.zig").panic;
const UserPtr = mem.safe.UserPtr;
const State = Process.State;
const cast = std.zig.c_translation.cast;

fn sys_wait4(
    self: *Process,
    pid: linux.pid_t,
    wstatus: ?UserPtr(*i32),
    options: i32,
    rusage: ?UserPtr(*linux.rusage),
    regs: *Process.UserRegs,
) !?linux.pid_t {
    _ = options;
    _ = rusage;

    return try scheduler.processWaitPid(self, pid, wstatus, regs);
}

pub fn handle_sys_wait4(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    regs: *Process.UserRegs,
) !usize {
    const pid = cast(linux.pid_t, arg0);
    const wstatus = UserPtr(*i32).fromFlatMaybeNull(arg1);
    const options = cast(i32, arg2);
    const rusage = UserPtr(*linux.rusage).fromFlatMaybeNull(arg3);
    if (try sys_wait4(self, pid, wstatus, options, rusage, regs)) |ret| {
        // The process we waited for has already exited, we didn't switch
        // processes and can continue.
        return cast(usize, ret);
    } else {
        // We have switched processes, don't overwrite rax (same as in sys_exit_group).
        return regs.rax;
    }
}
