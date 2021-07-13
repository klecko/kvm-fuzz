usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserCString = mem.safe.UserCString;
const UserSlice = mem.safe.UserSlice;

fn sys_readlink(self: *Process, pathname_ptr: UserCString, buf: UserSlice([]u8)) !usize {
    if (buf.len() == 0)
        return error.InvalidArgument;
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    assert(std.mem.eql(u8, pathname, "/proc/self/exe"));

    // Write path. Readlink does not append a null byte to buf.
    const size = std.math.min(self.elf_path.len, buf.len());
    try mem.safe.copyToUser(u8, buf, self.elf_path[0..size]);
    return size;
}

pub fn handle_sys_readlink(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const pathname_ptr = UserCString.fromFlat(arg0);
    const buf = UserSlice([]u8).fromFlat(arg1, arg2);
    return sys_readlink(self, pathname_ptr, buf);
}
