// The best would be importing as 'asm', but that's a keyword >:(
pub usingnamespace @import("./asm.zig");

pub const apic = @import("apic.zig");
pub const gdt = @import("gdt.zig");
pub const idt = @import("idt.zig");
pub const paging = @import("paging.zig");
pub const perf = @import("perf.zig");
pub const pit = @import("pit.zig");
pub const syscall = @import("syscall.zig");

const std = @import("std");

// Keep this the same as in the hypervisor (FaultInfo regs)
pub const Regs = extern struct {
    rax: usize = 0,
    rbx: usize = 0,
    rcx: usize = 0,
    rdx: usize = 0,
    rsi: usize = 0,
    rdi: usize = 0,
    rsp: usize = 0,
    rbp: usize = 0,
    r8: usize = 0,
    r9: usize = 0,
    r10: usize = 0,
    r11: usize = 0,
    r12: usize = 0,
    r13: usize = 0,
    r14: usize = 0,
    r15: usize = 0,
    rip: usize = 0,
    rflags: usize = 0,

    pub fn initFrom(other: anytype) Regs {
        const Type = @TypeOf(other);

        var regs: Regs = .{};
        inline for (comptime std.meta.fieldNames(Regs)) |field_name| {
            if (@hasField(Type, field_name)) {
                @field(regs, field_name) = @field(other, field_name);
            }
        }

        return regs;
    }
};
