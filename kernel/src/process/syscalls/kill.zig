usingnamespace @import("../common.zig");
const scheduler = @import("../../scheduler.zig");
const hypercalls = @import("../../hypercalls.zig");

fn sys_tgkill(self: *Process, tgid: linux.pid_t, tid: linux.pid_t, sig: i32) !void {
    const process = scheduler.processWithPID(tid) orelse return error.Search;
    if (process.tgid != tgid) return error.Search;
    const fault = hypercalls.FaultInfo{
        .fault_type = .AssertionFailed,
        .rip = 0, // TODO
        .fault_addr = 0,
        .kernel = false,
    };
    hypercalls.endRun(.Crash, &fault);
    // print("{} {} {}\n", .{ tgid, tid, sig });
    // TODO();
    // TIME TO DO FUTEX
}

pub fn handle_sys_tgkill(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const tgid = std.meta.cast(linux.pid_t, arg0);
    const tid = std.meta.cast(linux.pid_t, arg1);
    const sig = std.meta.cast(i32, arg1);
    try sys_tgkill(self, tgid, tid, sig);
    return 0;
}
