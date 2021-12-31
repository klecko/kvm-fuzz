const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const scheduler = @import("../../scheduler.zig");
const hypercalls = @import("../../hypercalls.zig");
const x86 = @import("../../x86/x86.zig");
const cast = std.zig.c_translation.cast;

fn sys_tgkill(
    self: *Process,
    tgid: linux.pid_t,
    tid: linux.pid_t,
    sig: i32,
    regs: *Process.UserRegs,
) !void {
    _ = self;
    _ = sig;
    const process = scheduler.processWithPID(tid) orelse return error.Search;
    if (process.tgid != tgid) return error.Search;
    const fault = hypercalls.FaultInfo{
        .fault_type = .AssertionFailed,
        .fault_addr = 0,
        .kernel = false,
        .regs = regs.*,
    };
    hypercalls.endRun(.Crash, &fault);
    // print("{} {} {}\n", .{ tgid, tid, sig });
    // TODO();
    // TIME TO DO FUTEX
}

pub fn handle_sys_tgkill(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    regs: *Process.UserRegs,
) !usize {
    const tgid = cast(linux.pid_t, arg0);
    const tid = cast(linux.pid_t, arg1);
    const sig = cast(i32, arg2);
    try sys_tgkill(self, tgid, tid, sig, regs);
    return 0;
}
