const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const UserSlice = mem.safe.UserSlice;
const cast = std.zig.c_translation.cast;

fn sys_read(self: *Process, fd: linux.fd_t, buf: UserSlice([]u8)) !usize {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    if (!file.isReadable())
        return error.BadFD;
    return file.read(buf);
}

pub fn handle_sys_read(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = cast(linux.fd_t, arg0);
    const buf = try UserSlice([]u8).fromFlat(arg1, arg2);
    return sys_read(self, fd, buf);
}

fn sys_pread64(
    self: *Process,
    fd: linux.fd_t,
    buf: UserSlice([]u8),
    offset: linux.off_t,
) !usize {
    if (offset < 0)
        return error.InvalidArgument;

    const file = self.files.table.get(fd) orelse return error.BadFD;
    if (!file.isReadable())
        return error.BadFD;

    // Change offset, read and restore offset
    const original_offset = file.offset;
    file.offset = @intCast(usize, offset);
    const ret = file.read(buf);
    file.offset = original_offset;
    return ret;
}

pub fn handle_sys_pread64(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) !usize {
    const fd = cast(linux.fd_t, arg0);
    const buf = try UserSlice([]u8).fromFlat(arg1, arg2);
    const offset = cast(linux.off_t, arg3);
    return sys_pread64(self, fd, buf, offset);
}
