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
    assert(flags & linux.O_WRONLY == 0 and flags & linux.O_RDWR == 0);

    // Get the pathname
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    log.debug("opening file '{s}'\n", .{pathname});

    // Check if the file exists
    if (!fs.file_manager.exists(pathname)) {
        log.warn("attempt to open unknown file '{s}'\n", .{pathname});
        return error.FileNotFound;
    }

    // Open it
    const fd = self.availableFd();
    const desc = try fs.file_manager.open(self.allocator, pathname, flags);
    errdefer desc.ref.unref();
    try self.files.table.put(fd, desc);
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
    const pathname_ptr = UserCString.fromFlat(arg1);
    const flags = std.meta.cast(i32, arg2);
    const mode = std.meta.cast(linux.mode_t, arg3);
    const ret = try sys_openat(self, dirfd, pathname_ptr, flags, mode);
    return std.meta.cast(usize, ret);
}

fn sys_close(self: *Process, fd: linux.fd_t) !void {
    if (self.files.table.fetchRemove(fd)) |kv| {
        kv.value.ref.unref();
    }
    return error.BadFD;
}

pub fn handle_sys_close(self: *Process, arg0: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    try sys_close(self, fd);
    return 0;
}
