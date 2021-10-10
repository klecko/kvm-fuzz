usingnamespace @import("../common.zig");

pub fn handle_sys_getpid(self: *Process) usize {
    return std.meta.cast(usize, self.tgid);
}

pub fn handle_sys_gettid(self: *Process) usize {
    return std.meta.cast(usize, self.pid);
}

pub fn handle_sys_getppid(self: *Process) usize {
    return std.meta.cast(usize, self.ptgid);
}

fn sys_getpgid(self: *Process, pid: linux.pid_t) !linux.pid_t {
    if (pid != 0)
        TODO();

    return self.pgid;
}

pub fn handle_sys_getpgid(self: *Process, arg0: usize) !usize {
    const pid = std.meta.cast(linux.pid_t, arg0);
    const ret = try sys_getpgid(self, pid);
    return std.meta.cast(usize, ret);
}
