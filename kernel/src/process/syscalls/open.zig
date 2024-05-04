const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const fs = @import("../../fs/fs.zig");
const UserCString = mem.safe.UserCString;
const log = std.log.scoped(.sys_openat);
const assert = std.debug.assert;
const cast = std.zig.c_translation.cast;

fn sys_openat(
    self: *Process,
    dirfd: linux.fd_t,
    pathname_ptr: UserCString,
    flags: linux.O,
    mode: linux.mode_t,
) !linux.fd_t {
    _ = mode;
    assert(dirfd == linux.AT.FDCWD);

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
    if (flags.CLOEXEC)
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
    const dirfd = cast(linux.fd_t, arg0);
    const pathname_ptr = try UserCString.fromFlat(arg1);
    const flags: linux.O = @bitCast(@as(u32, @truncate(arg2)));
    const mode = cast(linux.mode_t, arg3);
    const ret = try sys_openat(self, dirfd, pathname_ptr, flags, mode);
    return cast(usize, ret);
}

pub fn handle_sys_open(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
) !usize {
    return handle_sys_openat(self, cast(usize, @as(linux.fd_t, linux.AT.FDCWD)), arg0, arg1, arg2);
}

fn sys_close(self: *Process, fd: linux.fd_t) !void {
    const key_value = self.files.table.fetchRemove(fd) orelse return error.BadFD;
    key_value.value.ref.unref();
    self.files.unsetCloexec(fd);
}

pub fn handle_sys_close(self: *Process, arg0: usize) !usize {
    const fd = cast(linux.fd_t, arg0);
    try sys_close(self, fd);
    return 0;
}
