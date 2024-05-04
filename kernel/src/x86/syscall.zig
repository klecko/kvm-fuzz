const std = @import("std");
const assert = std.debug.assert;
const x86 = @import("x86.zig");
const scheduler = @import("../scheduler.zig");
const linux = @import("../linux.zig");
const Process = @import("../process/Process.zig");
const SegmentSelector = x86.gdt.SegmentSelector;
const log = std.log.scoped(.syscall);

export var kernel_stack: usize = undefined;
export var user_stack: usize = undefined;

export fn handleSyscall(
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    number: usize,
    regs: *Process.UserRegs,
) usize {
    const sys = std.meta.intToEnum(linux.SYS, number) catch return linux.errno(linux.E.NOSYS);
    const ret = scheduler.current().handleSyscall(sys, arg0, arg1, arg2, arg3, arg4, arg5, regs);
    return ret;
}

fn syscallEntry() callconv(.Naked) void {
    // Syscall places the return address into rcx, and rflags into r11.
    // We'll push a 0 for those registers.
    asm volatile (
    // Save user stack and set kernel stack
        \\mov %%rsp, (user_stack)
        \\mov (kernel_stack), %%rsp

        // Push registers
        \\push %%r11 // rflags
        \\push %%rcx // rip
        \\push %%r15
        \\push %%r14
        \\push %%r13
        \\push %%r12
        \\push $0    // r11, overwritten by rflags
        \\push %%r10
        \\push %%r9
        \\push %%r8
        \\push %%rbp
        \\push (user_stack) // rsp
        \\push %%rdi
        \\push %%rsi
        \\push %%rdx
        \\push $0    // rcx, overwritten by rip
        \\push %%rbx
        \\push %%rax

        // Push stack pointer as 8th argument for the handler
        \\push %%rsp

        // Push syscall number as 7th argument for the handler
        \\push %%rax

        // The fourth argument is set in r10. We need to move it to rcx to conform to
        // C ABI. Arguments should be in: rdi, rsi, rdx, rcx, r8, r9, stack.
        \\mov %%r10, %%rcx

        // Call syscall handler. Return value will be held in rax
        \\call handleSyscall

        // Scratch: 7th and 8th arguments for the handler
        \\pop %%rbx
        \\pop %%rbx

        // Restore registers
        \\pop %%rbx // don't restore rax, which now contains the return value
        \\pop %%rbx
        \\pop %%rcx
        \\pop %%rdx
        \\pop %%rsi
        \\pop %%rdi
        // We don't restore rsp yet, as we have more things in the stack we need.
        // We also can't ignore this value and just load from user_stack because
        // this value may have been overwritten. So just save it and restore it
        // later.
        \\pop %%rbp
        \\mov %%rbp, (user_stack)
        \\pop %%rbp
        \\pop %%r8
        \\pop %%r9
        \\pop %%r10
        \\pop %%r11
        \\pop %%r12
        \\pop %%r13
        \\pop %%r14
        \\pop %%r15
        \\pop %%rcx // Guest rip must be in rcx
        \\pop %%r11 // Guest rflags must be in r11

        // Restore user stack
        \\mov (user_stack), %%rsp

        // Return
        \\sysretq
    );
}

pub fn init() void {
    // SYSCALL instruction:
    //   CS.selector = STAR 47:32
    //   SS.selector = STAR 47:32 + 8
    // SYSRET instruction:
    //   CS.selector = STAR 63:48 + 16
    //   SS.selector = STAR 63:48 + 8
    comptime {
        assert(@intFromEnum(SegmentSelector.KernelData) == @intFromEnum(SegmentSelector.KernelCode) + 8);
        assert(@intFromEnum(SegmentSelector.UserCode) == @intFromEnum(SegmentSelector.UserData) + 8);
    }
    var star: usize = 0;
    star |= @as(usize, @intFromEnum(SegmentSelector.KernelCode)) << 32; // for syscall
    star |= @as(usize, @intFromEnum(SegmentSelector.UserData) - 8) << 48; // for sysret
    x86.wrmsr(.STAR, star);
    x86.wrmsr(.LSTAR, @intFromPtr(&syscallEntry));
    x86.wrmsr(.SYSCALL_MASK, 0x3F7FD5); // interrupts are disabled on syscall

    // Save kernel stack
    kernel_stack = asm volatile (
        \\mov %%rsp, %[ret]
        : [ret] "=r" (-> usize),
    );

    log.debug("Syscall handler initialized\n", .{});
}
