const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const common = @import("../../common.zig");
const scheduler = @import("../../scheduler.zig");
const UserPtr = mem.safe.UserPtr;
const print = common.print;
const TODO = common.TODO;
const cast = std.zig.c_translation.cast;

pub const Futex = struct {
    uaddr: usize,
    mask: u32,
};

const VariantArg = union {
    val2: u32,
    timeout: ?UserPtr(*linux.timespec),
};

fn futexOp(op_and_flags: i32) i32 {
    return op_and_flags & ~@as(i32, linux.FUTEX.PRIVATE_FLAG | linux.FUTEX.CLOCK_REALTIME);
}

fn futexWait(
    self: *Process,
    uaddr: UserPtr(*const u32),
    val: u32,
    mask: u32,
    regs: *Process.UserRegs,
) !void {
    std.debug.assert(mask != 0);

    const word = try mem.safe.copyFromUserSingle(u32, uaddr);
    if (word != val) {
        return error.TryAgain;
    }

    const futex = Futex{
        .uaddr = uaddr.flat(),
        .mask = mask,
    };
    self.state = Process.State{ .futex = futex };

    scheduler.schedule(regs);
    if (scheduler.current() == self)
        @panic("deadlock\n");
}

fn futexWake(
    self: *Process,
    uaddr: UserPtr(*const u32),
    val: u32,
    mask: u32,
) usize {
    _ = self;
    std.debug.assert(mask != 0);
    return scheduler.wakeProcessesWaitingForFutex(uaddr.flat(), mask, val);
}

fn sys_futex(
    self: *Process,
    uaddr: UserPtr(*const u32),
    futex_op: i32,
    val: u32,
    arg: VariantArg,
    uaddr2: ?UserPtr(*u32),
    val3: u32,
    regs: *Process.UserRegs,
) !usize {
    // TODO: timeouts
    _ = arg;
    _ = uaddr2;
    const op = futexOp(futex_op);
    // print("futex: {} {} {} {} {?} {}\n", .{ uaddr, futex_op, val, arg, uaddr2, val3 });
    switch (op) {
        linux.FUTEX.WAIT => {
            try futexWait(self, uaddr, val, linux.FUTEX_BITSET_MATCH_ANY, regs);
            return regs.rax; // we have switched: don't overwrite rax
        },
        linux.FUTEX.WAIT_BITSET => {
            if (val3 == 0)
                return error.InvalidArgument;
            try futexWait(self, uaddr, val, val3, regs);
            return regs.rax; // we have switched: don't overwrite rax
        },
        linux.FUTEX.WAKE => {
            return futexWake(self, uaddr, val, linux.FUTEX_BITSET_MATCH_ANY);
        },
        linux.FUTEX.WAKE_BITSET => {
            if (val3 == 0)
                return error.InvalidArgument;
            return futexWake(self, uaddr, val, val3);
        },
        else => TODO(),
    }
}

pub fn handle_sys_futex(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    regs: *Process.UserRegs,
) !usize {
    // Mandatory arguments
    const uaddr = try UserPtr(*const u32).fromFlat(arg0);
    const futex_op = cast(i32, arg1);
    const val = cast(u32, arg2);

    // Optional arguments depending on `op`
    const op = futexOp(futex_op);
    const arg = switch (op) {
        // These interpret the argument as a timeout, and may be null
        linux.FUTEX.WAIT,
        linux.FUTEX.WAIT_BITSET,
        linux.FUTEX.LOCK_PI,
        linux.FUTEX.WAIT_REQUEUE_PI,
        => VariantArg{ .timeout = try UserPtr(*linux.timespec).fromFlatMaybeNull(arg3) },
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
        => try UserPtr(*u32).fromFlat(arg4),
        else => null,
    };
    const val3 = cast(u32, arg5);

    const ret = try sys_futex(self, uaddr, futex_op, val, arg, uaddr2, val3, regs);
    return cast(usize, ret);
}
