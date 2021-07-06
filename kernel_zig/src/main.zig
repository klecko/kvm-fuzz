// We can't `usingnamespace @import("common.zig");` because that would import
// panic_fmt as panic, and we need it to be panic_root.
pub const log = @import("log.zig").log_root;
pub const panic = @import("panic.zig").panic_root;
const std = @import("std");
const print = @import("log.zig").print;
const x86 = @import("x86/x86.zig");
const pmm = @import("mem/pmm.zig");
const vmm = @import("mem/vmm.zig");
const hypercalls = @import("hypercalls.zig");

export fn kmain() noreturn {
    print("hello from zig\n", .{});

    x86.gdt.init();
    x86.idt.init();
    pmm.init();
    vmm.init();
    x86.apic.init();

    print("Done!\n", .{});
    hypercalls.endRun(.Exit, null);
}
