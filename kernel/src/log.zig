const std = @import("std");
const hypercalls = @import("hypercalls.zig");

fn writeFn(_: void, str: []const u8) !usize {
    hypercalls.print(str);
    return str.len;
}
const Writer = std.io.Writer(void, error{}, writeFn);

pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    var writer = Writer{ .context = {} };
    std.fmt.format(writer, format, args) catch unreachable;
}

pub fn logRoot(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const should_print = switch (scope) {
        .pmm => false,
        .vmm => false,
        .heap => false,
        .paging => false,
        else => true,
    };
    if (!should_print)
        return;

    const level_txt = "[" ++ @tagName(level) ++ "] ";
    const scope_txt = "[" ++ @tagName(scope) ++ "] ";
    print(scope_txt ++ level_txt ++ format, args);
}
