const std = @import("std");
const assert = std.debug.assert;
const Process = @import("../Process.zig");
const mem = @import("../../mem/mem.zig");
const UserCString = mem.safe.UserCString;
const UserSlice = mem.safe.UserSlice;
const cast = std.zig.c_translation.cast;

fn sys_readlink(self: *Process, pathname_ptr: UserCString, buf: UserSlice([]u8)) !usize {
    if (buf.len() == 0)
        return error.InvalidArgument;
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    const path_result = if (std.mem.eql(u8, pathname, "/proc/self/exe"))
        self.elf_path
    else {
        std.log.warn("readlink {s}, returning EINVAL\n", .{pathname});
        return error.InvalidArgument;
    };

    // Write path. Readlink does not append a null byte to buf.
    const size = std.math.min(path_result.len, buf.len());
    try mem.safe.copyToUser(u8, buf.sliceTo(size), path_result[0..size]);
    return size;
}

pub fn handle_sys_readlink(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const pathname_ptr = try UserCString.fromFlat(arg0);
    const buf = try UserSlice([]u8).fromFlat(arg1, arg2);
    return sys_readlink(self, pathname_ptr, buf);
}
