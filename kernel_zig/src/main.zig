// We can't `usingnamespace @import("common.zig");` because that would import
// panic_fmt as panic, and we need it to be panic_root.
pub const log = @import("log.zig").log_root;
pub const panic = @import("panic.zig").panic_root;
const std = @import("std");
const print = @import("log.zig").print;
const gdt = @import("x86/gdt.zig");
const idt = @import("x86/idt.zig");

export fn kmain() noreturn {
    print("hello from zig\n", .{});

    gdt.init();
    idt.init();
    // std.log.info("All your codebase are belong to us.\n", .{});

    const ptr = @intToPtr(*u8, 0x1);
    ptr.* = 5;

    var n: u8 = 255;
    n += 1;
    while (true) {}
}
