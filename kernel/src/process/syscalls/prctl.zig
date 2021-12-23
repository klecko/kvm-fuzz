const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const x86 = @import("../../x86/x86.zig");
const TODO = @import("../../common.zig").TODO;
const cast = std.zig.c_translation.cast;

fn sys_arch_prctl(self: *Process, code: i32, addr: usize) !void {
    _ = self;
    switch (code) {
        linux.ARCH.SET_FS => x86.wrmsr(.FS_BASE, addr),
        linux.ARCH.SET_GS, linux.ARCH.GET_FS, linux.ARCH.GET_GS => TODO(),
        else => return error.InvalidArgument,
    }
}

pub fn handle_sys_arch_prctl(self: *Process, arg0: usize, arg1: usize) !usize {
    const code = cast(i32, arg0);
    const addr = arg1;
    try sys_arch_prctl(self, code, addr);
    return 0;
}
