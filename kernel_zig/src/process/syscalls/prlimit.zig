usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;

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
        var limit: linux.rlimit = switch (resource) {
            .NOFILE => .{
                .cur = 1024,
                .max = 1024 * 1024,
            },
            .STACK => .{
                .cur = 8 * 1024 * 1024,
                .max = linux.RLIM_INFINITY,
            },
            else => TODO(),
        };
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
    const pid = std.meta.cast(linux.pid_t, arg0);
    const resource = std.meta.intToEnum(linux.rlimit_resource, arg1) catch return error.InvalidArgument;
    const new_limit_ptr = UserPtr(*const linux.rlimit).fromFlatMaybeNull(arg2);
    const old_limit_ptr = UserPtr(*linux.rlimit).fromFlatMaybeNull(arg3);
    try sys_prlimit(self, pid, resource, new_limit_ptr, old_limit_ptr);
    return 0;
}
