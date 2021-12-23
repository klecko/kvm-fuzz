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

pub const iovec = std.os.iovec;

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
        else => panic("unhandled error at errorToErrno: {}\n", .{err}),
    });
}

pub fn errno(linux_errno: linux.E) usize {
    return @bitCast(usize, -@intCast(isize, @enumToInt(linux_errno)));
}
