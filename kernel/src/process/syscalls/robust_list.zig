const std = @import("std");
const Process = @import("../Process.zig");
const mem = @import("../../mem/mem.zig");
const linux = @import("../../linux.zig");
const common = @import("../../common.zig");
const UserPtr = mem.safe.UserPtr;
const cast = std.zig.c_translation.cast;

fn fetchNextRobustEntry(entry: UserPtr(*const linux.robust_list)) !UserPtr(*const linux.robust_list) {
    // This basically returns entry.next wrapped in UserPtr and performing the memory access safely
    // TODO: check if both options work
    // Option1:
    // const next_entry_ptr = UserPtr(*const *const linux.robust_list).fromPtr(&entry.ptr().next.?);
    // var next_entry: *const linux.robust_list = undefined;
    // try mem.safe.copyFromUserSingle(*const linux.robust_list, &next_entry, next_entry_ptr);
    // return UserPtr(*const linux.robust_list).fromPtr(next_entry);

    // Option2:
    var tmp: linux.robust_list = undefined;
    try mem.safe.copyFromUserSingle(linux.robust_list, &tmp, entry);
    return UserPtr(*const linux.robust_list).fromPtr(tmp.next.?);
}

pub fn wakeRobustFutexes(self: *Process) void {
    //https://elixir.bootlin.com/linux/v6.1.12/source/kernel/futex/core.c#L773
    const head_ptr = self.robust_list_head orelse return;
    // var head = head_ptr.ptr();
    var head: linux.robust_list_head = undefined;
    mem.safe.copyFromUserSingle(linux.robust_list_head, &head, head_ptr) catch return;

    var entry = UserPtr(*const linux.robust_list).fromPtr(head.list.next.?) catch return;
    while (entry.ptr() != &head_ptr.ptr().list) {
        common.print("entry: {*}\n", .{entry.ptr()});
        common.TODO();
        entry = fetchNextRobustEntry(entry) catch return;
    }
}

fn sys_set_robust_list(
    self: *Process,
    head_ptr: ?UserPtr(*const linux.robust_list_head),
    len: usize,
) !void {
    std.debug.assert(len == @sizeOf(linux.robust_list_head));
    self.robust_list_head = head_ptr;
}

pub fn handle_sys_set_robust_list(self: *Process, arg0: usize, arg1: usize) !usize {
    const head_ptr = try UserPtr(*const linux.robust_list_head).fromFlatMaybeNull(arg0);
    const len = arg1;
    try sys_set_robust_list(self, head_ptr, len);
    return 0;
}
