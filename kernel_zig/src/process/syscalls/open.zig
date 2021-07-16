usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const fs = @import("../../fs/fs.zig");
const UserCString = mem.safe.UserCString;
const log = std.log.scoped(.sys_openat);

fn sys_openat(
    self: *Process,
    dirfd: linux.fd_t,
    pathname_ptr: UserCString,
    flags: i32,
    mode: linux.mode_t,
) !linux.fd_t {
    assert(dirfd == linux.AT_FDCWD);

    // Get the pathname
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    log.debug("opening file '{s}'\n", .{pathname});

    // Open file
    const file = try fs.file_manager.open(self.allocator, pathname, flags);
    errdefer file.ref.unref();

    // Insert it in our file descriptor table
    const fd = self.availableFd() orelse return error.NoFdAvailable;
    try self.files.table.put(fd, file);

    // Set file descriptor flags
    if (flags & linux.O_CLOEXEC != 0)
        self.files.setCloexec(fd);

    return fd;
}

pub fn handle_sys_openat(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) !usize {
    const dirfd = std.meta.cast(linux.fd_t, arg0);
    const pathname_ptr = try UserCString.fromFlat(arg1);
    const flags = std.meta.cast(i32, arg2);
    const mode = std.meta.cast(linux.mode_t, arg3);
    const ret = try sys_openat(self, dirfd, pathname_ptr, flags, mode);
    return std.meta.cast(usize, ret);
}

fn sys_close(self: *Process, fd: linux.fd_t) !void {
    const key_value = self.files.table.fetchRemove(fd) orelse return error.BadFD;
    key_value.value.ref.unref();
    self.files.unsetCloexec(fd);
}

pub fn handle_sys_close(self: *Process, arg0: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    try sys_close(self, fd);
    return 0;
}
