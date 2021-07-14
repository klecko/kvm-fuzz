usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserSlice = mem.safe.UserSlice;

fn sys_write(self: *Process, fd: linux.fd_t, buf: UserSlice([]const u8)) !usize {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    return file.write(file, buf);
}

pub fn handle_sys_write(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    const buf = try UserSlice([]const u8).fromFlat(arg1, arg2);
    return sys_write(self, fd, buf);
}
