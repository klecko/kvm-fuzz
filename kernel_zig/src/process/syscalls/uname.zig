usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;

fn unameHelper(comptime string: []const u8) [64:0]u8 {
    const zeroed_padding = [_:0]u8{0} ** std.math.max(0, 64 - string.len);
    return @ptrCast(*const [string.len]u8, string.ptr).* ++ zeroed_padding;
}

fn sys_uname(self: *Process, uname_ptr: UserPtr(*linux.utsname)) !void {
    comptime const uname = linux.utsname{
        .sysname = unameHelper("Linux"),
        .nodename = unameHelper("pep1t0"),
        .release = unameHelper("5.8.0-43-generic"),
        .version = unameHelper("#49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021"),
        .machine = unameHelper("x86_64"),
        .domainname = unameHelper("(none)"),
    };
    try mem.safe.copyToUserSingle(linux.utsname, uname_ptr, &uname);
}

pub fn handle_sys_uname(self: *Process, arg0: usize) !usize {
    const uname_ptr = try UserPtr(*linux.utsname).fromFlat(arg0);
    try sys_uname(self, uname_ptr);
    return 0;
}
