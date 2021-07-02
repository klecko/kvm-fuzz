usingnamespace @import("common.zig");
pub const log = @import("log.zig").log;
pub const panic = @import("panic.zig").panic;

export fn kmain() noreturn {
    // std.debug.print
    std.log.debug("hello {s}\n", .{"from zig"});
    print("hehe\n", .{});

    // std.log.info("All your codebase are belong to us.\n", .{});
    var n: u8 = 255;
    n += 1;
    while (true) {}
}
