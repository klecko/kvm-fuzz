// We can't `usingnamespace @import("common.zig");` because that would import
// panic_fmt as panic, and we need it to be panicRoot.
pub const log = @import("log.zig").logRoot;
pub const panic = @import("panic.zig").panicRoot;
// pub const os = @import("os/os.zig");
const std = @import("std");
const print = @import("log.zig").print;
const x86 = @import("x86/x86.zig");
const pmm = @import("mem/pmm.zig");
const vmm = @import("mem/vmm.zig");
const hypercalls = @import("hypercalls.zig");
const heap = @import("mem/heap.zig");

pub const log_level: std.log.Level = .info;

fn foo1() void {
    foo2();
}

fn foo2() void {
    foo3();
}

fn foo3() void {
    var n: u8 = 255;
    n += 1;
}

export fn kmain() noreturn {
    print("hello from zig\n", .{});

    x86.gdt.init();
    x86.idt.init();
    pmm.init();
    vmm.init();
    x86.perf.init();
    x86.apic.init();

    const p = vmm.page_allocator.alloc(u8, 1024 * 1024 * 10) catch null;
    print("memory: {}\nsecond attempt\n", .{pmm.amountFreeMemory()});
    std.debug.assert(p == null);
    const p2 = vmm.page_allocator.alloc(u8, 1024 * 1024 * 1) catch unreachable;
    print("{*}\n", .{p2});

    // foo3();

    print("Done!\n", .{});
    hypercalls.endRun(.Exit, null);
}
