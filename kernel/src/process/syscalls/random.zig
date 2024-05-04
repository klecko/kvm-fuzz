const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const UserSlice = mem.safe.UserSlice;
const cast = std.zig.c_translation.cast;

fn sys_getrandom(self: *Process, buf: UserSlice([]u8), flags: u32) !usize {
    _ = flags;
    _ = self;
    for (0..buf.len()) |i| {
        try mem.safe.copyToUserSingle(u8, buf.ptrAt(i), &@truncate(i));
    }
    return buf.len();
}

pub fn handle_sys_getrandom(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
) !usize {
    const buf = try UserSlice([]u8).fromFlat(arg0, arg1);
    const flags = cast(u32, arg2);
    return try sys_getrandom(self, buf, flags);
}
