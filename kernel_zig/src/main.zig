// We can't `usingnamespace @import("common.zig");` because that would import
// panic_fmt as panic, and we need it to be panicRoot.
pub const log = @import("log.zig").logRoot;
pub const panic = @import("panic.zig").panicRoot;
const std = @import("std");
const print = @import("log.zig").print;
const x86 = @import("x86/x86.zig");
const mem = @import("mem/mem.zig");
const hypercalls = @import("hypercalls.zig");
const fs = @import("fs/fs.zig");
const scheduler = @import("scheduler.zig");
const linux = @import("linux.zig");
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;
const Process = @import("process/Process.zig");

pub const log_level: std.log.Level = .info;
// pub const log_level: std.log.Level = .debug;

export fn kmain(argc: usize, argv: [*][*:0]const u8) noreturn {
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

    mem.heap.initHeapAllocator();
    // const allocator = mem.heap.page_allocator;
    const allocator = mem.heap.heap_allocator;
    // var gpa = mem.heap.GeneralPurposeAllocator(.{}){};
    // const allocator = &gpa.allocator;
    fs.file_manager.init(allocator, info.num_files);

    // var process = Process.initial(mem.heap.page_allocator, &info) catch unreachable;
    var process = Process.initial(allocator, &info) catch unreachable;
    scheduler.init(allocator, &process);
    process.startUser(argv[0..argc], &info) catch unreachable;

    // {
    //     const s = mem.safe.copyStringFromUser(allocator, UserPtr([*:0]const u8).fromFlat(info.elf_load_addr)) catch unreachable;
    //     defer allocator.free(s);
    // }

    {
        const test_allocator = allocator;
        print("memory before first attempt: {}\n", .{mem.pmm.amountFreeMemory()});
        const p = test_allocator.alloc(u8, 1024 * 1024 * 10) catch null;
        print("memory after first attempt: {}\n", .{mem.pmm.amountFreeMemory()});
        std.debug.assert(p == null);
        const p2 = test_allocator.alloc(u8, 1024 * 1024 * 1) catch unreachable;
        print("second attempt returned: {*}\n", .{p2});
        print("memory after second attempt: {}\n", .{mem.pmm.amountFreeMemory()});
        test_allocator.free(p2);
        print("memory after freeing second attempt: {}\n", .{mem.pmm.amountFreeMemory()});
    }

    // {
    //     var gpa2 = mem.heap.GeneralPurposeAllocator(.{}){};
    //     defer {
    //         const leaked = gpa2.deinit();
    //         std.debug.assert(!leaked);
    //     }
    //     const allocator2 = &gpa2.allocator;

    //     const stdout = fs.FileDescriptionStdout.create(allocator2) catch unreachable;
    //     const stdout_desc = &stdout.desc;
    //     defer stdout_desc.ref.unref();

    //     const stdout_desc2 = stdout_desc.ref.ref();
    //     defer stdout_desc2.ref.unref();

    //     std.debug.assert(stdout_desc == stdout_desc2);
    // }

    print("Done!\n", .{});
    hypercalls.endRun(.Exit, null);
}
