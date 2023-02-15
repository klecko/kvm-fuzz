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

// const Regs = struct {
//     rax: usize = 0,
//     rbx: usize = 0,
//     rcx: usize = 0,
//     rdx: usize = 0,
//     rbp: usize = 0,
//     rsi: usize = 0,
//     rdi: usize = 0,
//     r8: usize = 0,
//     r9: usize = 0,
//     r10: usize = 0,
//     r11: usize = 0,
//     r12: usize = 0,
//     r13: usize = 0,
//     r14: usize = 0,
//     r15: usize = 0,
//     rip: usize = 0,
// };

// fn foo() void {
//     print("Hi!!!!\n", .{});
//     // scheduler.schedule();
// }

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

    // TODO errdefer
    const pid = Process.getNextPid();
    const tgid = if (flags & linux.CLONE.THREAD != 0) self.tgid else pid;
    const ptgid = if (flags & linux.CLONE.THREAD != 0) self.ptgid else self.tgid;
    const space = if (flags & linux.CLONE.VM != 0) self.space else try self.space.clone();
    const files = if (flags & linux.CLONE.FILES != 0) self.files.ref.ref() else try self.files.clone();
    const fs_base = if (flags & linux.CLONE.SETTLS != 0) tls else self.fs_base;
    const signal_handlers = if (flags & linux.CLONE.SIGHAND != 0)
        self.signal_handlers
    else blk: {
        var tmp = try self.allocator.create([linux._NSIG]Process.Sigaction);
        std.mem.copy(Process.Sigaction, tmp, self.signal_handlers);
        break :blk tmp;
    };

    // const stack = try self.allocator.allocAdvanced(u8, std.mem.page_size, std.mem.page_size, .at_least);
    // var kernel_rsp = @ptrToInt(stack.ptr + stack.len);
    // const regs = Regs{
    //     .rip = @ptrToInt(foo),
    // };
    // kernel_rsp -= @sizeOf(Regs);
    // @intToPtr(*Regs, kernel_rsp).* = regs;

    var new_process = try self.allocator.create(Process);
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
    };
    new_process.user_regs.rax = 0;
    if (stack_ptr) |stack| {
        new_process.user_regs.rsp = stack.flat();
    }
    try scheduler.addProcess(new_process);

    if (flags & linux.CLONE.CHILD_SETTID != 0) {
        // This is thought to be done in the new process before returning to
        // userspace. As we can't do that because we are directly returning to
        // userspace, do it now loading its address space temporary.
        assert(child_tid_ptr != null);
        new_process.space.load();
        try mem.safe.copyToUserSingle(linux.pid_t, child_tid_ptr.?, &new_process.pid);
        self.space.load();
    }

    if (flags & linux.CLONE.PARENT_SETTID != 0) {
        assert(parent_tid_ptr != null);
        try mem.safe.copyToUserSingle(linux.pid_t, parent_tid_ptr.?, &new_process.pid);
    }

    common.print("process {} cloned, new pid {}\n", .{ self.pid, new_process.pid });
    return new_process.pid;
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
    const stack_ptr = UserPtr(*u8).fromFlatMaybeNull(arg1);
    const parent_tid_ptr = UserPtr(*linux.pid_t).fromFlatMaybeNull(arg2);
    const child_tid_ptr = UserPtr(*linux.pid_t).fromFlatMaybeNull(arg3);
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
