const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const scheduler = @import("../../scheduler.zig");
const x86 = @import("../../x86/x86.zig");
const FileDescriptorTable = @import("../FileDescriptorTable.zig");
const common = @import("../../common.zig");
const UserPtr = mem.safe.UserPtr;
const log = std.log.scoped(.sys_clone);
const assert = std.debug.assert;
const cast = std.zig.c_translation.cast;

const RETURN_TO_CHILD = true;

fn sys_clone(
    self: *Process,
    flags: u64,
    stack_ptr: ?UserPtr(*u8),
    parent_tid_ptr: ?UserPtr(*linux.pid_t),
    child_tid_ptr: ?UserPtr(*linux.pid_t),
    tls: u64,
    regs: *Process.UserRegs,
) !linux.pid_t {
    // fork: CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD
    // thread: CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
    //         CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
    //         CLONE_CHILD_CLEARTID

    // thread: 0x3d0f00 0x7ffff87fddf0 0x7ffff87fe9d0 0x7ffff87fe9d0 0x7ffff87fe700
    // fork:   0x1200011 0x0 0x0 0x6b3bd0 0x0
    const share_signal_handlers = flags & linux.CLONE.SIGHAND != 0;
    const clear_signal_handlers = flags & linux.CLONE.CLEAR_SIGHAND != 0;
    const share_vm = flags & linux.CLONE.VM != 0;
    const share_files = flags & linux.CLONE.FILES != 0;
    const is_thread = flags & linux.CLONE.THREAD != 0;

    if (share_signal_handlers and clear_signal_handlers)
        return error.InvalidArgument;
    if (share_signal_handlers and !share_vm)
        return error.InvalidArgument;
    if (is_thread and !share_signal_handlers)
        return error.InvalidArgument;

    // TODO errdefer
    const pid = Process.getNextPid();
    const tgid = if (is_thread) self.tgid else pid;
    const ptgid = if (is_thread) self.ptgid else self.tgid;
    const space = if (share_vm) self.space.ref.ref() else try self.space.clone();
    const files = if (share_files) self.files.ref.ref() else try self.files.clone();
    const fs_base = if (flags & linux.CLONE.SETTLS != 0) tls else self.fs_base;
    const signal_handlers = if (share_signal_handlers)
        self.signal_handlers // TODO ref counting
    else if (clear_signal_handlers)
        common.TODO()
    else blk: {
        var tmp = try self.allocator.create([linux._NSIG]Process.Sigaction);
        std.mem.copy(Process.Sigaction, tmp, self.signal_handlers);
        break :blk tmp;
    };
    const clear_child_tid_ptr = if (flags & linux.CLONE.CHILD_CLEARTID != 0) child_tid_ptr.? else null;

    const new_process = try self.allocator.create(Process);
    new_process.* = Process{
        .allocator = self.allocator,
        .pid = pid,
        .tgid = tgid,
        .pgid = self.pgid,
        .ptgid = ptgid,
        .state = .active,
        .space = space,
        .files = files,
        .elf_path = self.elf_path,
        .brk = self.brk,
        .min_brk = self.min_brk,
        .limits = self.limits,
        // .kernel_rsp = kernel_rsp,
        // .kernel_rsp0 = kernel_rsp,
        .user_regs = regs.*,
        .fs_base = fs_base,
        .blocked_signals = self.blocked_signals,
        .signal_handlers = signal_handlers,
        .robust_list_head = self.robust_list_head,
        .clear_child_tid_ptr = clear_child_tid_ptr,
    };
    if (stack_ptr) |stack| {
        new_process.user_regs.rsp = stack.flat();
    }
    try scheduler.addProcess(new_process);

    if (flags & linux.CLONE.PARENT_SETTID != 0) {
        assert(parent_tid_ptr != null);
        try mem.safe.copyToUserSingle(linux.pid_t, parent_tid_ptr.?, &new_process.pid);
    }

    if (RETURN_TO_CHILD) {
        scheduler.switchToProcess(new_process, regs);
        self.user_regs.rax = cast(usize, new_process.pid); // return value for parent
    } else {
        new_process.user_regs.rax = 0; // return value for child
    }

    if (flags & linux.CLONE.CHILD_SETTID != 0) {
        // We have to write the pid to the child address space. If we are
        // returning to the parent, then we are in the parent context and
        // therefore we need to load the child address space temporarily to
        // write the value. If we are returning to the child, at this point we
        // are already in the child context, so we can just write it.
        assert(child_tid_ptr != null);
        if (!RETURN_TO_CHILD) new_process.space.load();
        try mem.safe.copyToUserSingle(linux.pid_t, child_tid_ptr.?, &new_process.pid);
        if (!RETURN_TO_CHILD) self.space.load();
    }

    // common.print("process {} cloned, new pid {}\n", .{ self.pid, new_process.pid });
    return if (RETURN_TO_CHILD) 0 else new_process.pid;
}

pub fn handle_sys_clone(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    regs: *Process.UserRegs,
) !usize {
    const flags = arg0;
    const stack_ptr = try UserPtr(*u8).fromFlatMaybeNull(arg1);
    const parent_tid_ptr = try UserPtr(*linux.pid_t).fromFlatMaybeNull(arg2);
    const child_tid_ptr = try UserPtr(*linux.pid_t).fromFlatMaybeNull(arg3);
    const tls = arg4;
    const ret = try sys_clone(self, flags, stack_ptr, parent_tid_ptr, child_tid_ptr, tls, regs);
    return cast(usize, ret);
}

pub fn handle_sys_clone3(
    self: *Process,
    arg0: usize,
    arg1: usize,
    regs: *Process.UserRegs,
) !usize {
    const cl_args_ptr = try UserPtr(*const linux.clone_args).fromFlat(arg0);
    const size = arg1;

    std.debug.assert(@sizeOf(linux.clone_args) == size);
    var args: linux.clone_args = undefined;
    try mem.safe.copyFromUserSingle(linux.clone_args, &args, cl_args_ptr);

    // TODO: there are probably many options we are ignoring here

    return handle_sys_clone(
        self,
        args.flags,
        args.stack + args.stack_size,
        args.parent_tid,
        args.child_tid,
        args.tls,
        regs,
    );
}
