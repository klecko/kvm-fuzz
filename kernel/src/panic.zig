const std = @import("std");
const common = @import("common.zig");
const print = common.print;
const hypercalls = @import("hypercalls.zig");
const mem = @import("mem/mem.zig");
const x86 = @import("x86/x86.zig");
const StackTrace = std.builtin.StackTrace;

// https://github.com/ziglang/zig/issues/7962
pub fn panicRoot(msg: []const u8, error_return_trace: ?*StackTrace, ret_addr: ?usize) noreturn {
    _ = ret_addr;
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
        var frames_left: usize = @min(trace.index, trace.instruction_addresses.len);

        while (frames_left != 0) : ({
            frames_left -= 1;
            frame_index = (frame_index + 1) % trace.instruction_addresses.len;
        }) {
            const addr = trace.instruction_addresses[frame_index];
            print("\t{x}\n", .{addr});
        }
    }

    // We don't need to bother to print the stacktrace. As we are sending a
    // fault to the hypervisor, it will print it for us. Besides, the hypervisor
    // has access to debug info so it can print prettier stacktraces :')
    // print("dumping stacktrace\n", .{});
    // var it = std.debug.StackIterator.init(@returnAddress(), null);
    // while (it.next()) |addr| {
    //     print("\t{x}\n", .{addr});
    //     if (!mem.safe.isAddressInKernelRange(addr))
    //         break;
    // }

    // Send a fault to the hypervisor so the run stops and we can debug
    const fault = hypercalls.FaultInfo{
        .fault_type = .AssertionFailed,
        .fault_addr = 0,
        .kernel = true,
        .regs = x86.Regs.initFrom(hypercalls.StackTraceRegs.fromCurrent()),
    };
    hypercalls.endRun(.Crash, &fault);
}
