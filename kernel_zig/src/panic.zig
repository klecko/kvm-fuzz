usingnamespace @import("common.zig");
const hypercalls = @import("hypercalls.zig");
const StackTrace = std.builtin.StackTrace;

// https://github.com/ziglang/zig/issues/7962
pub fn panic_root(msg: []const u8, error_return_trace: ?*StackTrace) noreturn {
    if (error_return_trace) |trace| {
        print("woops there's error return trace?\n", .{});
    }
    panic("{s}\n", .{msg});
}

pub fn panic_fmt(comptime format: []const u8, args: anytype) noreturn {
    print("PANIC: " ++ format, args);
    print("dumping stacktrace\n", .{});
    var it = std.debug.StackIterator.init(@returnAddress(), null);
    while (it.next()) |addr| {
        print("\t{x}\n", .{addr});
    }

    // Send a fault to the hypervisor so the run stops and we can debug
    const fault = hypercalls.FaultInfo{
        .fault_type = .AssertionFailed,
        .rip = 0,
        .fault_addr = 0,
        .kernel = true,
    };
    hypercalls.endRun(.Crash, &fault);
}
