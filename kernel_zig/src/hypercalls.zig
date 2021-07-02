const builtin = @import("builtin");

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
        \\	mov $1, %rax;
        \\	jmp hypercall
    );
    check_equals(.Print, 1);
}

// pub extern fn test(arg: usize) void;
extern fn _print(s: [*]const u8) void;

pub fn print(s: []const u8) void {
    for (s) |c| {
        print_char(c);
    }
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
