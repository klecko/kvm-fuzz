usingnamespace @import("common.zig");
const StackTrace = std.builtin.StackTrace;

// https://github.com/ziglang/zig/issues/7962
pub fn panic(msg: []const u8, error_return_trace: ?*StackTrace) noreturn {
    print("PANIC: {s}\n", .{msg});
    if (error_return_trace) |trace| {
        print("woops there's error return trace?\n", .{});
    }

    var it = std.debug.StackIterator.init(@returnAddress(), null);
    while (it.next()) |addr| {
        print("{x}\n", .{addr});
    }
    while (true) {}
}
