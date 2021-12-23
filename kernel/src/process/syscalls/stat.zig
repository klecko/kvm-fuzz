const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const fs = @import("../../fs/fs.zig");
const UserCString = mem.safe.UserCString;
const UserPtr = mem.safe.UserPtr;
const cast = std.zig.c_translation.cast;

fn sys_fstat(self: *Process, fd: linux.fd_t, stat_ptr: UserPtr(*linux.Stat)) !void {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    return file.stat(file, stat_ptr);
}

pub fn handle_sys_fstat(self: *Process, arg0: usize, arg1: usize) !usize {
    const fd = cast(linux.fd_t, arg0);
    const stat_ptr = try UserPtr(*linux.Stat).fromFlat(arg1);
    try sys_fstat(self, fd, stat_ptr);
    return 0;
}

fn sys_stat(self: *Process, pathname_ptr: UserCString, stat_ptr: UserPtr(*linux.Stat)) !void {
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);
    return fs.file_manager.stat(pathname, stat_ptr);
}

pub fn handle_sys_stat(self: *Process, arg0: usize, arg1: usize) !usize {
    const pathname_ptr = try UserCString.fromFlat(arg0);
    const stat_ptr = try UserPtr(*linux.Stat).fromFlat(arg1);
    try sys_stat(self, pathname_ptr, stat_ptr);
    return 0;
}
