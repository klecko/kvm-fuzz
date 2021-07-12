usingnamespace @import("../common.zig");
const x86 = @import("x86.zig");
const scheduler = @import("../scheduler.zig");
const linux = @import("../linux.zig");
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
    regs: usize,
) usize {
    return scheduler.current().handleSyscall(@intToEnum(linux.SYS, number), arg0, arg1, arg2, arg3, arg4, arg5);
}

fn syscallEntry() callconv(.Naked) void {
    asm volatile (
    // Save user stack and set kernel stack
        \\mov %%rsp, (user_stack)
        \\mov (kernel_stack), %%rsp

        // Push registers
        \\push %%rcx
        \\push %%r11
        \\push %%r10
        \\push %%r9
        \\push %%r8
        \\push %%rbp
        \\push (user_stack)
        \\push %%rdi
        \\push %%rsi
        \\push %%rdx
        \\push %%rcx

        // Push stack pointer as 8th argument for the handler
        \\push %%rsp

        // Push syscall number as 7th argument for the handler
        \\push %%rax

        // The forth argument is set in r10. We need to move it to rcx to conform to
        // C ABI. Arguments should be in: rdi, rsi, rdx, rcx, r8, r9, stack.
        \\mov %%r10, %%rcx

        // Call syscall handler. Return value will be held in rax
        \\call handleSyscall

        // Restore registers
        // Scratch (syscall number) TODO: rsp also could be scratch ?
        \\pop %%rcx
        \\pop %%rsp
        \\pop %%rcx
        \\pop %%rdx
        \\pop %%rsi
        \\pop %%rdi
        // Scratch (rsp value)
        \\pop %%rbp
        \\pop %%rbp
        \\pop %%r8
        \\pop %%r9
        \\pop %%r10
        \\pop %%r11
        // Guest rip must be in rcx
        \\pop %%rcx

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
        assert(@enumToInt(SegmentSelector.KernelData) == @enumToInt(SegmentSelector.KernelCode) + 8);
        assert(@enumToInt(SegmentSelector.UserCode) == @enumToInt(SegmentSelector.UserData) + 8);
    }
    var star: usize = 0;
    star |= @as(usize, @enumToInt(SegmentSelector.KernelCode)) << 32; // for syscall
    star |= @as(usize, @enumToInt(SegmentSelector.UserData) - 8) << 48; // for sysret
    x86.wrmsr(.STAR, star);
    x86.wrmsr(.LSTAR, @ptrToInt(syscallEntry));
    x86.wrmsr(.SYSCALL_MASK, 0x3F7DD5);

    // Save kernel stack
    kernel_stack = asm volatile (
        \\mov %%rsp, %[ret]
        : [ret] "=r" (-> usize)
    );

    log.debug("Syscall handler initialized\n", .{});
}
