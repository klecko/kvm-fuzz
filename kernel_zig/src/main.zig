// We can't `usingnamespace @import("common.zig");` because that would import
// panic_fmt as panic, and we need it to be panicRoot.
pub const log = @import("log.zig").logRoot;
pub const panic = @import("panic.zig").panicRoot;
// pub const os = @import("os/os.zig");
const std = @import("std");
const print = @import("log.zig").print;
const x86 = @import("x86/x86.zig");
const mem = @import("mem/mem.zig");
const hypercalls = @import("hypercalls.zig");
const fs = @import("fs/fs.zig");
const linux = @import("linux.zig");
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;

pub const log_level: std.log.Level = .debug;

export fn kmain() noreturn {
    print("hello from zig\n", .{});

    var info: hypercalls.VmInfo = undefined;
    hypercalls.getInfo(&info);

    x86.gdt.init();
    x86.idt.init();
    mem.pmm.init();
    mem.vmm.init();
    x86.perf.init();
    x86.apic.init();
    fs.file_manager.init(info.num_files);

    var p1 = @intToPtr(*[5]u8, 7);
    var p2 = @intToPtr(*[5]u8, 6);
    const user_slice = UserSlice([]u8).fromSlice(p1);
    const h = mem.safe.copyFromUser(u8, p1, user_slice.toConst());
    print("{}\n", .{h});

    print("Done!\n", .{});
    hypercalls.endRun(.Exit, null);
}
