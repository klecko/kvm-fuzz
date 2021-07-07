usingnamespace @import("common.zig");
const hypercalls = @import("hypercalls.zig");
const StackTrace = std.builtin.StackTrace;

// https://github.com/ziglang/zig/issues/7962
pub fn panicRoot(msg: []const u8, error_return_trace: ?*StackTrace) noreturn {
    panicFmtErrorReturnTrace("{s}\n", .{msg}, error_return_trace);
}

pub fn panicFmt(comptime format: []const u8, args: anytype) noreturn {
    panicFmtErrorReturnTrace(format, args, null);
}

fn panicFmtErrorReturnTrace(comptime format: []const u8, args: anytype, error_return_trace: ?*StackTrace) noreturn {
    print("PANIC: " ++ format, args);

    if (error_return_trace) |trace| {
        // Similar to std.debug.writeStackTrace
        print("dumping error return trace:\n", .{});
        var frame_index: usize = 0;
        var frames_left: usize = std.math.min(trace.index, trace.instruction_addresses.len);

        while (frames_left != 0) : ({
            frames_left -= 1;
            frame_index = (frame_index + 1) % trace.instruction_addresses.len;
        }) {
            const addr = trace.instruction_addresses[frame_index];
            print("\t{x}\n", .{addr});
        }
    }

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
