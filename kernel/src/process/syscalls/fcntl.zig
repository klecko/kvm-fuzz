usingnamespace @import("../common.zig");
const fs = @import("../../fs/fs.zig");

fn sys_fcntl_dupfd(
    self: *Process,
    file: *fs.FileDescription,
    arg: usize,
    cloexec: bool,
) !usize {
    const fd_start = std.meta.cast(linux.fd_t, arg);
    if (fd_start >= self.limits.nofile.soft)
        return error.InvalidArgument;
    const new_fd = self.availableFdStartingOn(fd_start) orelse return error.NoFdAvailable;
    try self.files.table.put(new_fd, file.ref.ref());
    if (cloexec)
        self.files.setCloexec(new_fd);
    return std.meta.cast(usize, new_fd);
}

fn sys_fcntl(self: *Process, fd: linux.fd_t, cmd: i32, arg: u64) !usize {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    const ret = switch (cmd) {
        // F_GETFD and F_SETFD get and set the file descriptor flag FD_CLOEXEC.
        linux.F_GETFD => if (self.files.isCloexecSet(fd)) linux.FD_CLOEXEC else @as(usize, 0),
        linux.F_SETFD => blk: {
            self.files.setCloexecValue(fd, arg & linux.FD_CLOEXEC != 0);
            break :blk 0;
        },
        // Same as dup2, but uses the lowest-numbered available fd greater than
        // or equal to arg
        linux.F_DUPFD => try sys_fcntl_dupfd(self, file, arg, false),
        linux.F_DUPFD_CLOEXEC => try sys_fcntl_dupfd(self, file, arg, true),
        // Get file description flags
        linux.F_GETFL => std.meta.cast(usize, file.flags),
        else => TODO(),
    };
    return ret;
}

pub fn handle_sys_fcntl(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    const cmd = std.meta.cast(i32, arg1);
    const arg = arg2;
    return sys_fcntl(self, fd, cmd, arg);
}
