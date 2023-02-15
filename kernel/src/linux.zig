const std = @import("std");
const panic = @import("common.zig").panic;

// Export everything of std.os.linux
const linux = std.os.linux;
pub usingnamespace linux;

// Not available in std.os.linux
pub const clockid_t = i32;
pub const F_DUPFD_CLOEXEC = 1030;
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

pub const clone_args = extern struct {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
};

pub const iovec = std.os.iovec;

// Zig defines std.os.linux.NSIG as 65, but I believe it's wrong. It may be due
// to signals starting at 1 instead of 0.
// https://elixir.bootlin.com/linux/v6.1.12/source/arch/x86/include/asm/signal.h#L11
pub const _NSIG = 64;
pub const NSIG = undefined; // generate compiler error when using NSIG, since it's also defined by zig stdlib

pub fn errorToErrno(err: anyerror) usize {
    return errno(switch (err) {
        error.BadFD => linux.E.BADF,
        error.OutOfMemory => linux.E.NOMEM,
        error.NotUserRange, error.Fault => linux.E.FAULT,
        error.FileNotFound => linux.E.NOENT,
        error.InvalidArgument => linux.E.INVAL,
        error.NumericOutOfRange => linux.E.RANGE,
        error.NotConnected => linux.E.NOTCONN,
        error.NotSocket => linux.E.NOTSOCK,
        error.NoFdAvailable => linux.E.MFILE,
        error.PermissionDenied => linux.E.ACCES,
        error.Search => linux.E.SRCH,
        error.NoChild => linux.E.CHILD,
        else => panic("unhandled error at errorToErrno: {}\n", .{err}),
    });
}

pub fn errno(linux_errno: linux.E) usize {
    return @bitCast(usize, -@intCast(isize, @enumToInt(linux_errno)));
}
