const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;
const log = std.log.scoped(.sys_time);
const cast = std.zig.c_translation.cast;

fn sys_clock_gettime(
    self: *Process,
    clock_id: linux.clockid_t,
    tp_ptr: UserPtr(*linux.timespec),
) !void {
    _ = self;
    _ = clock_id;
    log.info("TODO\n", .{});
    const tp = linux.timespec{
        .tv_sec = 0,
        .tv_nsec = 0,
    };
    try mem.safe.copyToUserSingle(linux.timespec, tp_ptr, &tp);
}

pub fn handle_sys_clock_gettime(self: *Process, arg0: usize, arg1: usize) !usize {
    const clock_id = cast(linux.clockid_t, arg0);
    const tp_ptr = try UserPtr(*linux.timespec).fromFlat(arg1);
    try sys_clock_gettime(self, clock_id, tp_ptr);
    return 0;
}

fn sys_time(self: *Process, time_ptr: ?UserPtr(*linux.time_t)) !linux.time_t {
    _ = self;
    log.info("TODO time\n", .{});
    const time: linux.time_t = 0;
    if (time_ptr) |ptr| {
        try mem.safe.copyToUserSingle(linux.time_t, ptr, &time);
    }
    return time;
}

pub fn handle_sys_time(self: *Process, arg0: usize) !usize {
    const time_ptr = UserPtr(*linux.time_t).fromFlatMaybeNull(arg0);
    const ret = try sys_time(self, time_ptr);
    return cast(usize, ret);
}

fn sys_gettimeofday(
    self: *Process,
    tv_ptr: ?UserPtr(*linux.timeval),
    timezone_ptr: ?UserPtr(*linux.timezone),
) !void {
    std.debug.assert(timezone_ptr == null);
    if (tv_ptr) |ptr| {
        const tv = linux.timeval{
            .tv_sec = sys_time(self, null) catch unreachable,
            .tv_usec = 0,
        };
        try mem.safe.copyToUserSingle(linux.timeval, ptr, &tv);
    }
}

pub fn handle_sys_gettimeofday(self: *Process, arg0: usize, arg1: usize) !usize {
    const tv_ptr = UserPtr(*linux.timeval).fromFlatMaybeNull(arg0);
    const timezone_ptr = UserPtr(*linux.timezone).fromFlatMaybeNull(arg1);
    try sys_gettimeofday(self, tv_ptr, timezone_ptr);
    return 0;
}
