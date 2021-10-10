usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;
const log = std.log.scoped(.sys_clock_gettime);

fn sys_clock_gettime(
    self: *Process,
    clock_id: linux.clockid_t,
    tp_ptr: UserPtr(*linux.timespec),
) !void {
    log.info("TODO\n", .{});
    const tp = linux.timespec{
        .tv_sec = 0,
        .tv_nsec = 0,
    };
    try mem.safe.copyToUserSingle(linux.timespec, tp_ptr, &tp);
}

pub fn handle_sys_clock_gettime(self: *Process, arg0: usize, arg1: usize) !usize {
    const clock_id = std.meta.cast(linux.clockid_t, arg0);
    const tp_ptr = try UserPtr(*linux.timespec).fromFlat(arg1);
    try sys_clock_gettime(self, clock_id, tp_ptr);
    return 0;
}
