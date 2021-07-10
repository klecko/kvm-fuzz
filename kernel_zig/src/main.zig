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
// const RefCounter = @import("ref_counted.zig").RefCounter;
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;

pub const log_level: std.log.Level = .info;

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
    x86.syscall.init();
    fs.file_manager.init(info.num_files);

    print("memory before first attempt: {}\n", .{mem.pmm.amountFreeMemory()});
    const p = mem.vmm.page_allocator.alloc(u8, 1024 * 1024 * 10) catch null;
    print("memory after first attempt: {}\n", .{mem.pmm.amountFreeMemory()});
    std.debug.assert(p == null);
    const p2 = mem.vmm.page_allocator.alloc(u8, 1024 * 1024 * 1) catch unreachable;
    print("second attempt returned: {*}\n", .{p2});
    print("memory after second attempt: {}\n", .{mem.pmm.amountFreeMemory()});
    mem.vmm.page_allocator.free(p2);
    print("memory after freeing second attempt: {}\n", .{mem.pmm.amountFreeMemory()});

    // const p1 = @intToPtr(*u8, 5);
    // var val: u8 = undefined;
    // mem.safe.copyToUserSingle(u8, UserPtr(*u8).fromPtr(p1), &val) catch unreachable;

    {
        var gpa = mem.heap.GeneralPurposeAllocator(.{}){};
        defer {
            const leaked = gpa.deinit();
            std.debug.assert(!leaked);
        }
        const allocator = &gpa.allocator;

        const stdout = fs.FileDescriptionStdout.create(allocator) catch unreachable;
        const stdout_desc = &stdout.desc;
        defer stdout_desc.ref.unref();

        const stdout_desc2 = stdout_desc.ref.ref();
        defer stdout_desc2.ref.unref();

        std.debug.assert(stdout_desc == stdout_desc2);
    }

    print("Done!\n", .{});
    hypercalls.endRun(.Exit, null);
}
