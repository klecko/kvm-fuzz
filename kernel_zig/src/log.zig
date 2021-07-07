const std = @import("std");
const hypercalls = @import("hypercalls.zig");

fn writeFn(context: void, str: []const u8) !usize {
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
    const level_txt = "[" ++ @tagName(level) ++ "] ";
    const scope_txt = "[" ++ @tagName(scope) ++ "] ";
    print(scope_txt ++ level_txt ++ format, args);
}
