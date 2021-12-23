const std = @import("std");
const assert = std.debug.assert;
const Process = @import("../Process.zig");
const mem = @import("../../mem/mem.zig");
const UserSlice = mem.safe.UserSlice;
const UserCString = mem.safe.UserCString;
const cast = std.zig.c_translation.cast;

const cwd = "/home/leet";

fn sys_getcwd(self: *Process, buf: UserSlice([]u8)) !usize {
    _ = self;
    if (buf.len() < cwd.len + 1)
        return error.NumericOutOfRange;

    try mem.safe.copyToUser(u8, buf, std.mem.span(cwd)[0 .. cwd.len + 1]);
    return cwd.len + 1;
}

pub fn handle_sys_getcwd(self: *Process, arg0: usize, arg1: usize) !usize {
    const buf = try UserSlice([]u8).fromFlat(arg0, arg1);
    return sys_getcwd(self, buf);
}

fn sys_chdir(self: *Process, path_ptr: UserCString) !void {
    const path = try mem.safe.copyStringFromUser(self.allocator, path_ptr);
    defer self.allocator.free(path);

    assert(std.mem.eql(u8, path, cwd));
}

pub fn handle_sys_chdir(self: *Process, arg0: usize) !usize {
    const path_ptr = try UserCString.fromFlat(arg0);
    try sys_chdir(self, path_ptr);
    return 0;
}
