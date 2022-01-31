const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const common = @import("../../common.zig");
const UserPtr = mem.safe.UserPtr;
const print = common.print;
const TODO = common.TODO;
const cast = std.zig.c_translation.cast;

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
    _ = self;

    const op = futex_op & ~@as(i32, linux.FUTEX.PRIVATE_FLAG);
    if (op == linux.FUTEX.WAKE)
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
    const futex_op = cast(i32, arg1);
    const val = cast(i32, arg2);

    // Optional arguments depending on `op`
    const op = futex_op & ~@as(i32, linux.FUTEX.PRIVATE_FLAG);
    const arg = switch (op) {
        // These interpret the argument as a timeout, and may be null
        linux.FUTEX.WAIT,
        linux.FUTEX.WAIT_BITSET,
        linux.FUTEX.LOCK_PI,
        linux.FUTEX.WAIT_REQUEUE_PI,
        => VariantArg{ .timeout = UserPtr(*linux.timespec).fromFlatMaybeNull(arg3) },
        // These interpret the argument as val2
        linux.FUTEX.CMP_REQUEUE,
        linux.FUTEX.WAKE_OP,
        linux.FUTEX.CMP_REQUEUE_PI,
        => VariantArg{ .val2 = @truncate(u32, arg3) },
        else => undefined,
    };
    const uaddr2 = switch (op) {
        // These must have a uaddr2
        linux.FUTEX.CMP_REQUEUE,
        linux.FUTEX.WAKE_OP,
        linux.FUTEX.CMP_REQUEUE_PI,
        linux.FUTEX.WAIT_REQUEUE_PI,
        => try UserPtr(*i32).fromFlat(arg4),
        else => null,
    };
    const val3 = cast(i32, arg5);

    const ret = try sys_futex(self, uaddr, futex_op, val, arg, uaddr2, val3);
    return cast(usize, ret);
}
