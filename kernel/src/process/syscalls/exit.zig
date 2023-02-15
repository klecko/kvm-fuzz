const std = @import("std");
const Process = @import("../Process.zig");
const scheduler = @import("../../scheduler.zig");
const mem = @import("../../mem/mem.zig");
const linux = @import("../../linux.zig");
const cast = std.zig.c_translation.cast;

// fn sys_exit(self: *Process, status: i32, regs: *Process.UserRegs) usize {
//     scheduler.schedule(regs);
//     scheduler.removeProcess(self);
//     return regs.rax;
// }

fn sys_exit_group(self: *Process, status: i32, regs: *Process.UserRegs) usize {
    _ = status;

    self.wakeRobustFutexes();

    // Set with CLONE_CHILD_CLEARTID
    if (self.clear_child_tid_ptr) |ptr| {
        const value: i32 = 0;
        mem.safe.copyToUserSingle(i32, ptr, &value) catch {};
        _ = scheduler.wakeProcessesWaitingForFutex(ptr.flat(), linux.FUTEX_BITSET_MATCH_ANY, 1);
    }

    scheduler.exitCurrentProcessAndSchedule(regs);

    // Regs have been modified. We don't want to modify rax when returning a
    // a value, so just return the current value.
    // TODO: what about rcx/r11
    return regs.rax;
}

pub fn handle_sys_exit_group(self: *Process, arg0: usize, regs: *Process.UserRegs) usize {
    const status = cast(i32, arg0);
    return sys_exit_group(self, status, regs);
}

pub fn handle_sys_exit(self: *Process, arg0: usize, regs: *Process.UserRegs) usize {
    const status = cast(i32, arg0);
    return sys_exit_group(self, status, regs);
}
