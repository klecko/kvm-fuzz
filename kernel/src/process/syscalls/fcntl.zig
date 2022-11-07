const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const fs = @import("../../fs/fs.zig");
const common = @import("../../common.zig");
const cast = std.zig.c_translation.cast;

fn sys_fcntl_dupfd(
    self: *Process,
    file: *fs.FileDescription,
    fd_start: linux.fd_t,
    cloexec: bool,
) !linux.fd_t {
    if (fd_start >= self.limits.nofile.soft)
        return error.InvalidArgument;
    const new_fd = self.availableFdStartingOn(fd_start) orelse return error.NoFdAvailable;
    try self.files.table.put(new_fd, file.ref.ref());
    if (cloexec)
        self.files.setCloexec(new_fd);
    return new_fd;
}

fn sys_fcntl(self: *Process, fd: linux.fd_t, cmd: i32, arg: u64) !usize {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    const ret = switch (cmd) {
        // F_GETFD and F_SETFD get and set the file descriptor flag FD_CLOEXEC.
        linux.F.GETFD => if (self.files.isCloexecSet(fd)) linux.FD_CLOEXEC else @as(i32, 0),
        linux.F.SETFD => blk: {
            self.files.setCloexecValue(fd, arg & linux.FD_CLOEXEC != 0);
            break :blk 0;
        },

        // Same as dup2, but uses the lowest-numbered available fd greater than
        // or equal to arg
        linux.F.DUPFD => try sys_fcntl_dupfd(self, file, cast(linux.fd_t, arg), false),
        linux.F_DUPFD_CLOEXEC => try sys_fcntl_dupfd(self, file, cast(linux.fd_t, arg), true),

        // Get file description flags
        linux.F.GETFL => file.flags,

        linux.F.SETLKW => 0,

        else => common.panic("unhandled fcntl cmd: {}, arg: {}\n", .{ cmd, arg }),
    };
    return cast(usize, ret);
}

pub fn handle_sys_fcntl(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = cast(linux.fd_t, arg0);
    const cmd = cast(i32, arg1);
    const arg = arg2;
    return sys_fcntl(self, fd, cmd, arg);
}
