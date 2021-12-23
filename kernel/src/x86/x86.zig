// The best would be importing as 'asm', but that's a keyword >:(
pub usingnamespace @import("./asm.zig");

pub const apic = @import("apic.zig");
pub const gdt = @import("gdt.zig");
pub const idt = @import("idt.zig");
pub const paging = @import("paging.zig");
pub const perf = @import("perf.zig");
pub const pit = @import("pit.zig");
pub const syscall = @import("syscall.zig");
