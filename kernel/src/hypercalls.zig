const std = @import("std");
const x86 = @import("x86/x86.zig");
const linux = @import("linux.zig");
const fs = @import("fs/fs.zig");
const common = @import("common.zig");
const printFmt = common.print;
const panic = common.panic;

pub const Hypercall = enum(c_int) {
    Test,
    Print,
    GetMemInfo,
    GetKernelBrk,
    GetInfo,
    GetFileInfo,
    SubmitFilePointers,
    SubmitTimeoutPointers,
    PrintStackTrace,
    LoadLibrary,
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
    user_entry: usize,
    elf_entry: usize,
    elf_load_addr: usize,
    interp_start: usize,
    interp_end: usize,
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

// Keep this the same as in the hypervisor
pub const FaultInfo = extern struct {
    fault_type: Type,
    fault_addr: usize,
    kernel: bool,
    regs: x86.Regs,

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
        _ = fmt;
        _ = options;
        try std.fmt.format(
            writer,
            "Fault{{ .fault_type = {s}, .rip = 0x{x}, .fault_addr = 0x{x}, .kernel = {} }}",
            .{ @tagName(self.fault_type), self.regs.rip, self.fault_addr, self.kernel },
        );
    }
};

// Keep this the same as in the hypervisor
pub const StackTraceRegs = struct {
    rsp: usize,
    rbp: usize,
    rip: usize,

    pub fn fromCurrent() StackTraceRegs {
        return .{
            .rip = getRip(),
            .rbp = @frameAddress(),
            .rsp = asm volatile ("mov %%rsp, %[ret]"
                : [ret] "=r" (-> usize),
            ),
        };
    }

    pub fn from(other: anytype) StackTraceRegs {
        return .{
            .rip = other.rip,
            .rbp = other.rbp,
            .rsp = other.rsp,
        };
    }
};

// Keep this the same as in the hypervisor
pub const RunEndReason = enum(c_int) {
    Exit,
    Breakpoint,
    Debug,
    Crash,
    Timeout,
    Unknown,
};

fn checkEquals(comptime hc: Hypercall, comptime n: u8) void {
    if (@enumToInt(hc) != n) {
        @compileError("woops, hypercall " ++ @tagName(hc) ++ " has wrong value");
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
        \\.global getFileInfo
        \\getFileInfo:
        \\  mov $5, %rax
        \\  jmp hypercall
        \\
        \\.global submitFilePointers
        \\submitFilePointers:
        \\  mov $6, %rax
        \\  jmp hypercall
        \\
        \\.global submitTimeoutPointers
        \\submitTimeoutPointers:
        \\  mov $7, %rax
        \\  jmp hypercall
        \\
        \\.global _printStackTrace
        \\_printStackTrace:
        \\  mov $8, %rax
        \\  jmp hypercall
        \\
        \\.global loadLibrary
        \\loadLibrary:
        \\  mov $9, %rax
        \\  jmp hypercall
        \\
        \\.global _endRun
        \\endRun:
        \\	mov $10, %rax
        \\	jmp hypercall
        \\
        \\.global getRip
        \\getRip:
        \\movq (%rsp), %rax
        \\ret
    );
    checkEquals(.Print, 1);
    checkEquals(.GetMemInfo, 2);
    checkEquals(.GetKernelBrk, 3);
    checkEquals(.GetInfo, 4);
    checkEquals(.GetFileInfo, 5);
    checkEquals(.SubmitFilePointers, 6);
    checkEquals(.SubmitTimeoutPointers, 7);
    checkEquals(.PrintStackTrace, 8);
    checkEquals(.LoadLibrary, 9);
    checkEquals(.EndRun, 10);
}

// pub extern fn test(arg: usize) void;
extern fn _print(s: [*]const u8) void;
pub extern fn getMemInfo(info: *MemInfo) void;
pub extern fn getKernelBrk() usize;
pub extern fn getInfo(info: *VmInfo) void;
pub extern fn getFileLen(n: usize) usize;

// Returns path in `path_buf` and file length in `length_ptr`
pub extern fn getFileInfo(n: usize, path_buf: [*]u8, length_ptr: *usize) void;

pub extern fn submitFilePointers(n: usize, buf: [*]u8, length_ptr: *usize) void;
pub extern fn submitTimeoutPointers(timer_ptr: *usize, timeout_ptr: *usize) void;
extern fn _printStackTrace(stacktrace_regs: *const StackTraceRegs) void;
pub extern fn endRun(reason: RunEndReason, info: ?*const FaultInfo) noreturn;
extern fn loadLibrary(filename: [*]const u8, filename_len: usize, load_addr: usize) void;
extern fn getRip() usize;

pub fn print(s: []const u8) void {
    for (s) |c| {
        printChar(c);
    }
}

var interpreter_range = struct {
    start: usize = 0,
    end: usize = 0,
}{};

pub fn setInterpreterRange(start: usize, end: usize) void {
    interpreter_range.start = start;
    interpreter_range.end = end;
}

pub fn maybeLoadLibrary(mmap_addr: usize, mmap_file: []const u8, rip: usize) void {
    // Check if mmap syscall was called from the interpreter
    if (!(interpreter_range.start <= rip and rip < interpreter_range.end))
        return;

    // Get the filename of the library and tell the hypervisor to load it
    const filename = fs.file_manager.filenameFromFileContent(mmap_file) orelse return;
    loadLibrary(filename.ptr, filename.len, mmap_addr);
}

pub fn printStackTrace(stacktrace_regs: ?*const StackTraceRegs) void {
    // If we weren't given regs, use current ones
    const arg = stacktrace_regs orelse &StackTraceRegs.fromCurrent();
    _printStackTrace(arg);
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
