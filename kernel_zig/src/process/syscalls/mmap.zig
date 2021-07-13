usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");

fn protToMemPerms(prot: i32) mem.Perms {
    assert(prot & linux.PROT_GROWSDOWN == 0 and prot & linux.PROT_GROWSUP == 0);
    return mem.Perms{
        .read = (prot & linux.PROT_READ) != 0,
        .write = (prot & linux.PROT_WRITE) != 0,
        .exec = (prot & linux.PROT_EXEC) != 0,
    };
}

fn sys_mmap(
    self: *Process,
    addr: UserPtr(*u8),
    length: usize,
    prot: i32,
    flags: i32,
    fd: fd_t,
    offset: usize,
) usize {
    TODO();
    // log.debug("mmap(0x{x}, {}, 0x{x}, 0x{x}, {}, 0x{x}\n", .{ addr.flat(), length, prot, flags, fd, offset });

    // const supported_flags = linux.MAP_PRIVATE | linux.MAP_SHARED | linux.MAP_ANONYMOUS |
    //     linux.MAP_FIXED | linux.MAP_DENYWRITE | linux.MAP_STACK;
    // assert(flags & supported_flags == flags);

    // // Check given file descriptor is valid
    // if (fd != -1 and !self.files.table.contains(fd))
    //     return -linux.EBADF;

    // // We must return EINVAL if no length, and ENOMEM if length wraps
    // // TODO: currently we would panic if length wraps.
    // if (length == 0)
    //     return -linux.EINVAL;
    // const length_aligned = mem.alignPageForward(length);
    // if (length_aligned == 0)
    //     return -linux.ENOMEM;

    // const map_private = (flags & linux.MAP_PRIVATE) != 0;
    // const map_shared = (flags & linux.MAP_SHARED) != 0;
    // const map_anonymous = (flags & linux.MAP_ANONYMOUS) != 0;
    // const map_fixed = (flags & linux.MAP_FIXED) != 0;

    // // Shared and private: choose one
    // if (map_shared and map_private)
    //     return -linux.EINVAL;
    // if (!map_shared and !map_private)
    //     return -linux.EINVAL;

    // // If MAP_FIXED, addr can't be null or not aligned
    // if (map_fixed and (addr.isNull() or !mem.isPageAligned(addr.flat())))
    //     return -linux.EINVAL;

    // // Get permisions. If we're mapping a file, map it as writable first
    // // so we can write its contents.
    // var perms = protToMemPerms(prot);
    // if (fd != -1)
    //     perms.write = true;

    // const flags = mem.AddressSpace.MapFlags{
    //     .discardAlreadyMapped = map_fixed,
    //     .shared = map_shared,
    // };

    // self.space.mapRange(addr.flat(), length_aligned, perms, flags);
}

fn sys_mprotect(self: *Process, addr: usize, length: usize, prot: i32) !void {
    if (!mem.isPageAligned(addr))
        return error.InvalidArgument;

    // TODO: wrapping
    const length_aligned = mem.alignPageForward(length);
    self.space.setRangePerms(addr, length_aligned, protToMemPerms(prot)) catch return error.OutOfMemory;
}

pub fn handle_sys_mprotect(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const addr = arg0;
    const length = arg1;
    const prot = std.meta.cast(i32, arg2);
    try sys_mprotect(self, addr, length, prot);
    return 0;
}
