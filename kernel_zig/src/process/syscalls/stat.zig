usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const fs = @import("../../fs/fs.zig");
const UserCString = mem.safe.UserCString;
const UserPtr = mem.safe.UserPtr;

fn sys_fstat(self: *Process, fd: linux.fd_t, stat_ptr: UserPtr(*linux.stat)) !void {
    if (self.files.table.get(fd)) |desc| {
        return desc.stat(desc, stat_ptr);
    }
    return error.BadFD;
}

pub fn handle_sys_fstat(self: *Process, arg0: usize, arg1: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    const stat_ptr = UserPtr(*linux.stat).fromFlat(arg1);
    try sys_fstat(self, fd, stat_ptr);
    return 0;
}

fn sys_stat(self: *Process, pathname_ptr: UserCString, stat_ptr: UserPtr(*linux.stat)) !void {
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    if (!fs.file_manager.exists(pathname))
        return error.FileNotFound;

    return fs.file_manager.stat(pathname, stat_ptr);
}

pub fn handle_sys_stat(self: *Process, arg0: usize, arg1: usize) !usize {
    const pathname_ptr = UserCString.fromFlat(arg0);
    const stat_ptr = UserPtr(*linux.stat).fromFlat(arg1);
    try sys_stat(self, pathname_ptr, stat_ptr);
    return 0;
}
