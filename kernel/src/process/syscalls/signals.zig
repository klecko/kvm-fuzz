const std = @import("std");
const Process = @import("../Process.zig");
const mem = @import("../../mem/mem.zig");
const linux = @import("../../linux.zig");
const common = @import("../../common.zig");
const UserPtr = mem.safe.UserPtr;
const cast = std.zig.c_translation.cast;
const Sigset = Process.Sigset;
const Sigaction = Process.Sigaction;
const SIG = linux.SIG;

fn checkSigsetSize(sigsetsize: usize) void {
    std.debug.assert(sigsetsize == Sigset.bit_length / 8);
}

fn sys_rt_sigprocmask(
    self: *Process,
    how: i32,
    set_ptr: ?UserPtr(*const Sigset),
    oldset_ptr: ?UserPtr(*Sigset),
    sigsetsize: usize,
) !void {
    checkSigsetSize(sigsetsize);
    if (oldset_ptr) |ptr| {
        try mem.safe.copyToUserSingle(Sigset, ptr, &self.blocked_signals);
    }
    if (set_ptr) |ptr| {
        const set = try mem.safe.copyFromUserSingle(Sigset, ptr);
        if (how == SIG.BLOCK) {
            self.blocked_signals.setUnion(set);
        } else if (how == SIG.UNBLOCK) {
            self.blocked_signals.mask &= ~set.mask;
        } else if (how == SIG.SETMASK) {
            self.blocked_signals.mask = set.mask;
        } else return error.InvalidArgument;
    }

    // common.print("rt_sigprocmask {} {?} {?} {}\n", .{ how, set_ptr, oldset_ptr, sigsetsize });
}

pub fn handle_sys_rt_sigprocmask(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) !usize {
    const how = cast(i32, arg0);
    const set_ptr = try UserPtr(*const Sigset).fromFlatMaybeNull(arg1);
    const oldset_ptr = try UserPtr(*Sigset).fromFlatMaybeNull(arg2);
    const sigsetsize = arg3;
    try sys_rt_sigprocmask(self, how, set_ptr, oldset_ptr, sigsetsize);
    return 0;
}

fn sigmask(signum: u6) usize {
    std.debug.assert(signum != 0);
    return 1 << (signum - 1);
}

// const SIG_DEFAULT_MASK = struct {
//     const KILL =
// }

fn sys_rt_sigaction(
    self: *Process,
    signum_: i32,
    act_ptr: ?UserPtr(*const Sigaction),
    oldact_ptr: ?UserPtr(*Sigaction),
    sigsetsize: usize,
) !void {
    checkSigsetSize(sigsetsize);

    // TODO: there are probably many more things to do here
    // https://elixir.bootlin.com/linux/v6.1.12/source/kernel/signal.c#L4087

    // signum can be NSIG because they start at 1 instead of 0
    if (signum_ < 1 or signum_ > linux._NSIG or signum_ == SIG.KILL or signum_ == SIG.STOP)
        return error.InvalidArgument;

    const signum: usize = @intCast(signum_);
    if (oldact_ptr) |ptr| {
        try mem.safe.copyToUserSingle(Sigaction, ptr, &self.signal_handlers[signum - 1]);
    }

    if (act_ptr) |ptr| {
        // TODO sanitize?
        self.signal_handlers[signum - 1] = try mem.safe.copyFromUserSingle(Sigaction, ptr);
    }
}

pub fn handle_sys_rt_sigaction(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) !usize {
    const signum = cast(i32, arg0);
    const act_ptr = try UserPtr(*const Sigaction).fromFlatMaybeNull(arg1);
    const oldact_ptr = try UserPtr(*Sigaction).fromFlatMaybeNull(arg2);
    const sigsetsize = arg3;
    try sys_rt_sigaction(self, signum, act_ptr, oldact_ptr, sigsetsize);
    return 0;
}
