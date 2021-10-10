usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;

const VariantArg = union {
    val2: u32,
    timeout: ?UserPtr(*linux.timespec),
};

fn sys_futex(
    self: *Process,
    uaddr: UserPtr(*i32),
    futex_op: i32,
    val: i32,
    arg: VariantArg,
    uaddr2: ?UserPtr(*i32),
    val3: i32,
) !i32 {
    const op = futex_op & ~@as(i32, linux.FUTEX_PRIVATE_FLAG);
    print("futex: {}\n", .{futex_op});
    if (op == linux.FUTEX_WAKE)
        return 0;
    print("{} {} {} {} {} {}\n", .{ uaddr, futex_op, val, arg, uaddr2, val3 });
    TODO();
}

pub fn handle_sys_futex(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) !usize {
    // Mandatory arguments
    const uaddr = try UserPtr(*i32).fromFlat(arg0);
    const futex_op = std.meta.cast(i32, arg1);
    const val = std.meta.cast(i32, arg2);

    // Optional arguments depending on `op`
    const op = futex_op & ~@as(i32, linux.FUTEX_PRIVATE_FLAG);
    const arg = switch (op) {
        // These interpret the argument as a timeout, and may be null
        linux.FUTEX_WAIT, linux.FUTEX_WAIT_BITSET, linux.FUTEX_LOCK_PI, linux.FUTEX_WAIT_REQUEUE_PI => VariantArg{ .timeout = UserPtr(*linux.timespec).fromFlatMaybeNull(arg3) },
        // These interpret the argument as val2
        linux.FUTEX_CMP_REQUEUE,
        linux.FUTEX_WAKE_OP,
        linux.FUTEX_CMP_REQUEUE_PI,
        => VariantArg{ .val2 = @truncate(u32, arg3) },
        else => undefined,
    };
    const uaddr2 = switch (op) {
        // These must have a uaddr2
        linux.FUTEX_CMP_REQUEUE, linux.FUTEX_WAKE_OP, linux.FUTEX_CMP_REQUEUE_PI, linux.FUTEX_WAIT_REQUEUE_PI => try UserPtr(*i32).fromFlat(arg4),
        else => null,
    };
    const val3 = std.meta.cast(i32, arg5);

    const ret = try sys_futex(self, uaddr, futex_op, val, arg, uaddr2, val3);
    return std.meta.cast(usize, ret);
}
