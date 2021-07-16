usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const log = std.log.scoped(.sys_clone);

fn sys_clone(
    flags: u64,
    stack_ptr: UserPtr(*u8),
    parent_tid_ptr: UserPtr(*linux.pid_t),
    child_tid_ptr: UserPtr(*linux.pid_t),
    tls: u64,
) !u32 {}
