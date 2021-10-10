pub const std = @import("std");
pub const print = @import("log.zig").print;
pub const panic = @import("panic.zig").panicFmt;
pub const assert = std.debug.assert;

pub fn TODO() noreturn {
    print("TODO AT 0x{x}\n", .{@returnAddress()});
    unreachable;
}
