const std = @import("std");
pub const log = @import("log.zig").logRoot;
pub const panic = @import("panic.zig").panicRoot;

const common = @import("common.zig");
const x86 = @import("x86/x86.zig");
const mem = @import("mem/mem.zig");
const hypercalls = @import("hypercalls.zig");
const fs = @import("fs/fs.zig");
const scheduler = @import("scheduler.zig");
const Process = @import("process/Process.zig");
const print = common.print;

pub const log_level: std.log.Level = .info;
// pub const log_level: std.log.Level = .debug;

export fn kmain(argc: usize, argv: [*][*:0]const u8) noreturn {
    std.log.info("hello from zig\n", .{});

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
    // const allocator = mem.heap.heap_allocator;
    // const allocator = mem.heap.block_allocator;
    const allocator = mem.heap.gpa_allocator;

    fs.file_manager.init(allocator, info.num_files);

    var process = Process.initial(allocator, &info) catch unreachable;
    scheduler.init(allocator, &process);
    process.startUser(argv[0..argc], &info) catch unreachable;
    unreachable;
}
