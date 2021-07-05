// We can't `usingnamespace @import("common.zig");` because that would import
// panic_fmt as panic, and we need it to be panic_root.
pub const log = @import("log.zig").log_root;
pub const panic = @import("panic.zig").panic_root;
const std = @import("std");
const print = @import("log.zig").print;
const x86 = @import("x86/x86.zig");
const pmm = @import("mem/pmm.zig");

export fn kmain() noreturn {
    print("hello from zig\n", .{});

    x86.gdt.init();
    x86.idt.init();
    pmm.init();
    // std.log.info("All your codebase are belong to us.\n", .{});

    var page_table = x86.paging.PageTable.init(x86.rdcr3());
    var pte = page_table.ensurePTE(0) catch unreachable;
    pte.setFrameBase(pmm.allocFrame() catch unreachable);
    pte.setPresent(true);
    pte.setWritable(true);

    const ptr = @intToPtr(*u8, 0x1);
    ptr.* = 5;

    var n: u8 = 255;
    n += 1;
    while (true) {}
}
