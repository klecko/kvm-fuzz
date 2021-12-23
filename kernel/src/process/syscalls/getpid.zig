const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const TODO = @import("../../common.zig").TODO;
const cast = std.zig.c_translation.cast;

fn sys_getpid(self: *Process) linux.pid_t {
    return self.tgid;
}

pub fn handle_sys_getpid(self: *Process) usize {
    return cast(usize, sys_getpid(self));
}

fn sys_gettid(self: *Process) linux.pid_t {
    return self.pid;
}

pub fn handle_sys_gettid(self: *Process) usize {
    return cast(usize, sys_gettid(self));
}

fn sys_getppid(self: *Process) linux.pid_t {
    return self.ptgid;
}

pub fn handle_sys_getppid(self: *Process) usize {
    return cast(usize, sys_getppid(self));
}

fn sys_getpgid(self: *Process, pid: linux.pid_t) !linux.pid_t {
    if (pid != 0)
        TODO();

    return self.pgid;
}

pub fn handle_sys_getpgid(self: *Process, arg0: usize) !usize {
    const pid = cast(linux.pid_t, arg0);
    const ret = try sys_getpgid(self, pid);
    return cast(usize, ret);
}
