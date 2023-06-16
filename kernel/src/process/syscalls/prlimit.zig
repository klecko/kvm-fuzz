const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const TODO = @import("../../common.zig").TODO;
const UserPtr = mem.safe.UserPtr;
const assert = std.debug.assert;
const cast = std.zig.c_translation.cast;

const Limit = struct {
    hard: usize,
    soft: usize,
};

pub const Limits = struct {
    nofile: Limit,
    stack: Limit,

    pub fn default() Limits {
        return Limits{ .nofile = .{
            .hard = 1024 * 1024,
            .soft = 1024,
        }, .stack = .{
            .soft = mem.layout.user_stack_size,
            .hard = linux.RLIM.INFINITY,
        } };
    }

    pub fn get(self: Limits, resource: linux.rlimit_resource) linux.rlimit {
        const limit = switch (resource) {
            .NOFILE => self.nofile,
            .STACK => self.stack,
            else => TODO(),
        };
        return linux.rlimit{
            .cur = limit.soft,
            .max = limit.hard,
        };
    }
};

fn sys_prlimit(
    self: *Process,
    pid: linux.pid_t,
    resource: linux.rlimit_resource,
    new_limit_ptr: ?UserPtr(*const linux.rlimit),
    old_limit_ptr: ?UserPtr(*linux.rlimit),
) !void {
    // PID 0 refers to the calling process' PID
    assert(pid == self.pid or pid == 0);

    if (old_limit_ptr) |ptr| {
        const limit = self.limits.get(resource);
        try mem.safe.copyToUserSingle(linux.rlimit, ptr, &limit);
    }

    if (new_limit_ptr) |_| {
        switch (resource) {
            .CORE => {},
            else => TODO(),
        }
    }
}

pub fn handle_sys_prlimit(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) !usize {
    const pid = cast(linux.pid_t, arg0);
    const resource = std.meta.intToEnum(linux.rlimit_resource, arg1) catch return error.InvalidArgument;
    const new_limit_ptr = try UserPtr(*const linux.rlimit).fromFlatMaybeNull(arg2);
    const old_limit_ptr = try UserPtr(*linux.rlimit).fromFlatMaybeNull(arg3);
    try sys_prlimit(self, pid, resource, new_limit_ptr, old_limit_ptr);
    return 0;
}
