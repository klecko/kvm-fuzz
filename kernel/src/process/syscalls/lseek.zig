const std = @import("std");
const Process = @import("../Process.zig");
const TODO = @import("../../common.zig").TODO;
const linux = @import("../../linux.zig");
const fd_t = linux.fd_t;
const off_t = linux.off_t;
const cast = std.zig.c_translation.cast;

fn sys_lseek(self: *Process, fd: fd_t, offset: off_t, whence: i32) !off_t {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    var ret = switch (whence) {
        linux.SEEK.SET => offset,
        linux.SEEK.CUR => @intCast(off_t, file.offset) + offset,
        linux.SEEK.END => @intCast(off_t, file.size()) + offset,
        else => TODO(),
    };
    if (ret < 0)
        return error.InvalidArgument;
    file.offset = @intCast(usize, ret);
    return ret;
}

pub fn handle_sys_lseek(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = cast(fd_t, arg0);
    const offset = cast(off_t, arg1);
    const whence = cast(i32, arg2);
    const ret = try sys_lseek(self, fd, offset, whence);
    return cast(usize, ret);
}
