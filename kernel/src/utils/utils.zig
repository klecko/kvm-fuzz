pub const RefCounter = @import("ref_counter.zig").RefCounter;

const std = @import("std");

fn formatNumberAsMemory(
    n: usize,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    var n_new: usize = undefined;
    var unit: []const u8 = undefined;
    if (n < 1024) {
        // Bytes
        n_new = n;
        unit = "B";
    } else if (n < 1024 * 1024) {
        // Kilobytes
        n_new = n / 1024;
        unit = "K";
    } else if (n < 1024 * 1024 * 1024) {
        // Megabytes
        n_new = n / (1024 * 1024);
        unit = "M";
    } else {
        // Gigabytes
        n_new = n / (1024 * 1024 * 1024);
        unit = "G";
    }
    try std.fmt.format(writer, "{}{s}", .{ n_new, unit });
}

pub fn fmtNumberAsMemory(n: usize) std.fmt.Formatter(formatNumberAsMemory) {
    return .{ .data = n };
}
