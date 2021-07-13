usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserSlice = mem.safe.UserSlice;

// pub fn sys_read(self: *Process, fd: linux.fd_t, buf: UserSlice([]u8)) isize {
// 	return if (self.files.table.get(fd)) |file_desc_ptr|
// 		file_desc_ptr.read(file_desc_ptr, buf)
// 	else
// 		-linux.EBADF;
// }

fn sys_read(self: *Process, fd: linux.fd_t, buf: UserSlice([]u8)) !usize {
    return if (self.files.table.get(fd)) |file_desc_ptr|
        file_desc_ptr.read(file_desc_ptr, buf)
    else
        error.BadFD;
}

pub fn handle_sys_read(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    const buf = UserSlice([]u8).fromFlat(arg1, arg2);
    return sys_read(self, fd, buf);
}
