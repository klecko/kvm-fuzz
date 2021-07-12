// usingnamespace @import("common.zig");
const std = @import("std");
const x86 = @import("x86/x86.zig");
const linux = @import("linux.zig");

pub const Hypercall = enum(c_int) {
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
const phinfo_t = extern struct {
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
};

// Keep this the same as in the hypervisor
pub const VmInfo = extern struct {
    elf_path: [linux.PATH_MAX]u8,
    brk: usize,
    num_files: usize,
    unused1: usize,
    unused2: usize,
    user_entry: usize,
    elf_entry: usize,
    elf_load_addr: usize,
    interp_base: usize,
    phinfo: phinfo_t,
    term: linux.termios,
};

// Keep this the same as in the hypervisor
pub const MemInfo = extern struct {
    mem_start: usize,
    mem_length: usize,
    physmap_vaddr: usize,
};

// Keep this the same as in the hypervisor
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

    pub fn format(
        self: FaultInfo,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try std.fmt.format(
            writer,
            "Fault{{ .fault_type = {s}, .rip = 0x{x}, .fault_addr = 0x{x}, .kernel = {} }}",
            .{ @tagName(self.fault_type), self.rip, self.fault_addr, self.kernel },
        );
    }
};

const RunEndReason = enum(c_int) {
    Exit,
    Debug,
    Crash,
    Timeout,
    Unknown = -1,
};

fn checkEquals(comptime hc: Hypercall, comptime n: u8) void {
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
        \\.global getKernelBrk
        \\getKernelBrk:
        \\  mov $3, %rax
        \\  jmp hypercall
        \\
        \\.global getInfo
        \\getInfo:
        \\  mov $4, %rax
        \\  jmp hypercall
        \\
        \\.global getFileLen
        \\getFileLen:
        \\  mov $5, %rax
        \\  jmp hypercall
        \\
        \\.global getFileName
        \\getFileName:
        \\  mov $6, %rax
        \\  jmp hypercall
        \\
        \\.global submitFilePointers
        \\submitFilePointers:
        \\  mov $7, %rax
        \\  jmp hypercall
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
    checkEquals(.Print, 1);
    checkEquals(.GetMemInfo, 2);
    checkEquals(.GetKernelBrk, 3);
    checkEquals(.GetInfo, 4);
    checkEquals(.GetFileLen, 5);
    checkEquals(.GetFileName, 6);
    checkEquals(.SubmitFilePointers, 7);
    checkEquals(.SubmitTimeoutPointers, 8);
    checkEquals(.EndRun, 10);
}

// pub extern fn test(arg: usize) void;
extern fn _print(s: [*]const u8) void;
pub extern fn getMemInfo(info: *MemInfo) void;
pub extern fn getKernelBrk() usize;
pub extern fn getInfo(info: *VmInfo) void;
pub extern fn getFileLen(n: usize) usize;
pub extern fn getFileName(n: usize, buf: [*]u8) void;
pub extern fn submitFilePointers(n: usize, buf: [*]u8, length_ptr: *usize) void;
pub extern fn submitTimeoutPointers(timer_ptr: *usize, timeout_ptr: *usize) void;
extern fn _endRun(reason: RunEndReason, info: ?*const FaultInfo, instr_executed: usize) noreturn;

pub fn print(s: []const u8) void {
    for (s) |c| {
        printChar(c);
    }
}

const pmm = @import("mem/mem.zig").pmm;
const log = @import("log.zig");
pub fn endRun(reason: RunEndReason, info: ?*const FaultInfo) noreturn {
    // log.print("frames allocated: {}\n", .{pmm.numberOfAllocations()});
    _endRun(reason, info, x86.perf.instructionsExecuted());
}

const buf_len = 1024;
var out_buf: [buf_len]u8 = undefined;
var used: usize = 0;
fn printChar(c: u8) void {
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
