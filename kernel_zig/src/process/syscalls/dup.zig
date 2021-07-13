fn sys_dup(self: *Process, old_fd: fd_t) i32 {
    // Dup old_fd into the first available fd
    if (self.files.table.get(old_fd)) |desc| {
        const new_fd = self.availableFd();
        self.files.table.put(new_fd, desc.ref.ref());
        return new_fd;
    }
    return -linux.EBADF;
}

fn sys_dup2(self: *Process, old_fd: fd_t, new_fd: fd_t) i32 {
    if (old_fd == new_fd)
        return old_fd;

    if (self.files.table.get(old_fd)) |old_desc| {
        // Get the entry corresponding to new_fd and place old_desc there.
        // If it already existed, unref the desc first.
        const new_fd_entry = self.files.table.getOrPut(new_fd);
        if (new_fd_entry.found_existing) {
            new_fd_entry.value_ptr.ref.unref();
        }
        new_fd_entry.value_ptr.* = old_desc.ref.ref();
        return new_fd;
    }

    return -linux.EBADF;
}
