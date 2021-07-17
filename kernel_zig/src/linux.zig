pub usingnamespace @import("linux_std");
usingnamespace @import("common.zig");

pub const clockid_t = i32;
pub const F_DUPFD_CLOEXEC = 1030;

// We can't use the std kernel_stat, because it defines uid_t as std.os.linux.uid_t,
// which is not imported in freestanding. Instead, here we directly import uid_t
// from linux_std.
pub const stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    nlink: usize,

    mode: u32,
    uid: uid_t,
    gid: gid_t,
    __pad0: u32 = undefined,
    rdev: dev_t,
    size: off_t,
    blksize: isize,
    blocks: i64,

    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [3]isize = undefined,
};

pub const sysinfo = extern struct {
    uptime: i64,
    loads: [3]u64,
    total_ram: u64,
    free_ram: u64,
    shared_ram: u64,
    buffer_ram: u64,
    total_swap: u64,
    free_swap: u64,
    procs: u16,
    __pad1: u16 = 0,
    total_high: u64,
    free_high: u64,
    mem_unit: u32,
};

pub const iovec = extern struct {
    iov_base: [*]u8,
    iov_len: u64,
};

pub fn errorToErrno(err: anyerror) usize {
    return @bitCast(usize, @as(isize, switch (err) {
        error.BadFD => -EBADF,
        error.OutOfMemory => -ENOMEM,
        error.NotUserRange, error.Fault => -EFAULT,
        error.FileNotFound => -ENOENT,
        error.InvalidArgument => -EINVAL,
        error.NumericOutOfRange => -ERANGE,
        error.NotConnected => -ENOTCONN,
        error.NotSocket => -ENOTSOCK,
        error.NoFdAvailable => -EMFILE,
        else => panic("unhandled error at errorToErrno: {}\n", .{err}),
    }));
}
