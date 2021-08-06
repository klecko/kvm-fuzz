usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const scheduler = @import("../../scheduler.zig");
const x86 = @import("../../x86/x86.zig");
const FileDescriptorTable = @import("../FileDescriptorTable.zig");
const UserPtr = mem.safe.UserPtr;
const log = std.log.scoped(.sys_clone);

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
    const tgid = if (flags & linux.CLONE_THREAD != 0) self.tgid else pid;
    const space = if (flags & linux.CLONE_VM != 0) self.space else try self.space.clone();
    const files = if (flags & linux.CLONE_FILES != 0)
        self.files.ref.ref()
    else
        try FileDescriptorTable.createDefault(self.allocator, self.limits.nofile.hard);

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
        .space = space,
        .files = files,
        .elf_path = self.elf_path,
        .brk = self.brk,
        .min_brk = self.min_brk,
        .limits = self.limits,
        // .kernel_rsp = kernel_rsp,
        // .kernel_rsp0 = kernel_rsp,
        .user_regs = regs.*,
    };
    new_process.user_regs.rax = 0;
    try scheduler.addProcess(new_process);

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
    const ret = sys_clone(self, flags, stack_ptr, parent_tid_ptr, child_tid_ptr, tls, regs) catch unreachable;
    return std.meta.cast(usize, ret);
}
