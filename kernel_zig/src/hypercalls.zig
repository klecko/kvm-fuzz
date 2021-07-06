const x86 = @import("x86/x86.zig");

pub const Hypercall = enum {
    Test,
    Print,
    GetMemInfo,
    GetKernelBrk,
    GetInfo,
    GetFileLen,
    GetFileName,
    SubmitFilePointers,
    SubmitTimeoutPointers,
    PrintStacktrace,
    EndRun,
};

// Keep this the same as in the hypervisor
pub const MemInfo = struct {
    mem_start: usize,
    mem_length: usize,
    physmap_vaddr: usize,
};

pub const FaultInfo = extern struct {
    fault_type: Type,
    rip: usize,
    fault_addr: usize,
    kernel: bool,

    pub const Type = enum(c_int) {
        Read,
        Write,
        Exec,
        OutOfBoundsRead,
        OutOfBoundsWrite,
        OutOfBoundsExec,
        AssertionFailed,
        DivByZero,
        GeneralProtectionFault,
        StackSegmentFault,
    };
};

const RunEndReason = enum(c_int) {
    Exit,
    Debug,
    Crash,
    Timeout,
    Unknown = -1,
};

fn check_equals(comptime hc: Hypercall, comptime n: u8) void {
    if (@enumToInt(hc) != n) {
        @compileError("woops, hypercall " ++ @tagName(hc) ++
            " has wrong value");
    }
}
comptime {
    asm (
        \\.global hypercall
        \\hypercall:
        \\	outb %al, $16;
        \\	ret;
        \\
        // \\.global hc_test
        // \\hc_test:
        // \\	mov $0, %rax;
        // \\	jmp hypercall
        \\
        \\.global _print
        \\_print:
        \\	mov $1, %rax
        \\	jmp hypercall
        \\
        \\.global getMemInfo
        \\getMemInfo:
        \\	mov $2, %rax
        \\	jmp hypercall
        \\
        \\.global submitTimeoutPointers
        \\submitTimeoutPointers:
        \\  mov $8, %rax
        \\  jmp hypercall
        \\
        \\.global _endRun
        \\_endRun:
        \\	mov $10, %rax
        \\	jmp hypercall
    );
    check_equals(.Print, 1);
    check_equals(.GetMemInfo, 2);
    check_equals(.SubmitTimeoutPointers, 8);
    check_equals(.EndRun, 10);
}

// pub extern fn test(arg: usize) void;
extern fn _print(s: [*]const u8) void;
pub extern fn getMemInfo(info: *MemInfo) void;
pub extern fn submitTimeoutPointers(timer_ptr: *usize, timeout_ptr: *usize) void;
extern fn _endRun(reason: RunEndReason, info: ?*const FaultInfo, instr_executed: usize) noreturn;

pub fn print(s: []const u8) void {
    for (s) |c| {
        print_char(c);
    }
}

pub fn endRun(reason: RunEndReason, info: ?*const FaultInfo) noreturn {
    _endRun(reason, info, x86.perf.instructionsExecuted());
}

const buf_len = 1024;
var out_buf: [buf_len]u8 = undefined;
var used: usize = 0;
fn print_char(c: u8) void {
    out_buf[used] = c;
    used += 1;
    if (c == '\n' or used == buf_len - 1) {
        out_buf[used] = 0;
        _print(&out_buf);
        used = 0;
    }
}

// TODO: try and do this better

// In this case, it seems like @ptrCast in getHypercall is not working as expected,
// and says hypercall() has 0 arguments.
// fn hypercallFunctionType(hc: Hypercall) type {
//     return switch (hc) {
//         .Print => fn ([*]const u8) void,
//         else => fn () void,
//     };
// }

// fn getHypercall(comptime hc: Hypercall) hypercallFunctionType(hc) {
//     const ret = struct {
//         fn hypercall() void {
//             asm volatile (
//                 \\mov %[hc_num], %%rax
//                 \\jmp hypercall
//                 :
//                 : [hc_num] "im" (@enumToInt(hc))
//             );
//         }
//     }.hypercall;
//     return @ptrCast(hypercallFunctionType(hc), ret);
// }
// const _print = getHypercall(.Print);

// extern fn hypercall() void;

// fn hypercall2(comptime n: Hypercall) type {
//     return struct {
//         fn call(arg: usize) callconv(.Naked) void {
//             asm volatile ("jmp hypercall"
//                 :
//                 : [n] "{al}" (n),
//                   [arg] "{rdi}" (arg)
//             );
//         }
//     };
// }

// pub fn hc_test(arg: usize) void {
//     hypercall2(.Test).call(arg);
// }

// fn hypercall(n: Hypercall, arg1: usize) callconv(.Naked) void {
//     asm volatile (
//         \\outb %[n], $16;
//         \\ret;
//         // : [arg1] "={rdi}" (arg1)
//         :
//         : [n] "{al}" (n)
//         : "rax", "rdi"
//     );
// }

// pub noinline fn hc_test(arg: usize) callconv(.Naked) void {
//     // hypercall(.Print, arg);
//     // hypercall(.Print);
// }
