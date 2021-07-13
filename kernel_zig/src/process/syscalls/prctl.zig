usingnamespace @import("../common.zig");
const x86 = @import("../../x86/x86.zig");

fn sys_arch_prctl(self: *Process, code: i32, addr: usize) !void {
    switch (code) {
        linux.ARCH_SET_FS => x86.wrmsr(.FS_BASE, addr),
        linux.ARCH_SET_GS, linux.ARCH_GET_FS, linux.ARCH_GET_GS => TODO(),
        else => return error.InvalidArgument,
    }
}

pub fn handle_sys_arch_prctl(self: *Process, arg0: usize, arg1: usize) !usize {
    const code = std.meta.cast(i32, arg0);
    const addr = arg1;
    try sys_arch_prctl(self, code, addr);
    return 0;
}
