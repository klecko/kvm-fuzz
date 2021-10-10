usingnamespace @import("../common.zig");
const fd_t = linux.fd_t;

fn sys_dup(self: *Process, old_fd: fd_t) !fd_t {
    // Dup old_fd into the first available fd
    const file = self.files.table.get(old_fd) orelse return error.BadFD;
    const new_fd = self.availableFd() orelse return error.NoFdAvailable;
    try self.files.table.put(new_fd, file.ref.ref());
    return new_fd;
}

pub fn handle_sys_dup(self: *Process, arg0: usize) !usize {
    const old_fd = std.meta.cast(fd_t, arg0);
    const ret = try sys_dup(self, old_fd);
    return std.meta.cast(usize, ret);
}

fn sys_dup2(self: *Process, old_fd: fd_t, new_fd: fd_t) !fd_t {
    if (old_fd == new_fd)
        return old_fd;
    if (new_fd >= self.limits.nofile.soft)
        return error.BadFD;

    // Get the entry corresponding to new_fd and place old_file there.
    // If the entry already had a file, unref it first.
    const old_file = self.files.table.get(old_fd) orelse return error.BadFD;
    const new_fd_entry = try self.files.table.getOrPut(new_fd);
    if (new_fd_entry.found_existing) {
        new_fd_entry.value_ptr.*.ref.unref();
    }
    new_fd_entry.value_ptr.* = old_file.ref.ref();
    return new_fd;
}

pub fn handle_sys_dup2(self: *Process, arg0: usize, arg1: usize) !usize {
    const old_fd = std.meta.cast(fd_t, arg0);
    const new_fd = std.meta.cast(fd_t, arg1);
    const ret = try sys_dup2(self, old_fd, new_fd);
    return std.meta.cast(usize, ret);
}
