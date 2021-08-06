usingnamespace @import("../common.zig");
const scheduler = @import("../../scheduler.zig");

fn sys_exit(self: *Process, status: i32, regs: *Process.UserRegs) usize {
    scheduler.schedule(regs);
    scheduler.removeProcess(self);
    return regs.rax;
}

pub fn handle_sys_exit(self: *Process, arg0: usize, regs: *Process.UserRegs) usize {
    const status = std.meta.cast(i32, arg0);
    return sys_exit(self, status, regs);
}

fn sys_exit_group(self: *Process, status: i32, regs: *Process.UserRegs) usize {
    scheduler.schedule(regs);
    scheduler.removeProcess(self);
    return regs.rax;
}

pub fn handle_sys_exit_group(self: *Process, arg0: usize, regs: *Process.UserRegs) usize {
    const status = std.meta.cast(i32, arg0);
    return sys_exit_group(self, status, regs);
}
