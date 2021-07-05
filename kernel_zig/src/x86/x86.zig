// The best would be importing as 'asm', but that's a keyword >:(
usingnamespace @import("./asm.zig");

pub const gdt = @import("gdt.zig");
pub const idt = @import("idt.zig");
pub const paging = @import("paging.zig");
