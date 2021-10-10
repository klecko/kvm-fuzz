usingnamespace @import("../common.zig");
const scheduler = @import("../../scheduler.zig");

// fn sys_exit(self: *Process, status: i32, regs: *Process.UserRegs) usize {
//     scheduler.schedule(regs);
//     scheduler.removeProcess(self);
//     return regs.rax;
// }

pub fn handle_sys_exit(self: *Process, arg0: usize, regs: *Process.UserRegs) usize {
    const status = std.meta.cast(i32, arg0);
    return sys_exit_group(self, status, regs);
}

fn sys_exit_group(self: *Process, status: i32, regs: *Process.UserRegs) usize {
    scheduler.removeActiveProcessAndSchedule(regs);

    // Regs have been modified. We don't want to modify rax when returning a
    // a value, so just return the current value.
    // TODO: what about rcx/r11
    return regs.rax;
}

pub fn handle_sys_exit_group(self: *Process, arg0: usize, regs: *Process.UserRegs) usize {
    const status = std.meta.cast(i32, arg0);
    return sys_exit_group(self, status, regs);
}
