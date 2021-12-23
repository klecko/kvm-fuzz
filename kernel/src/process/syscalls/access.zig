const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const fs = @import("../../fs/fs.zig");
const UserCString = mem.safe.UserCString;
const log = std.log.scoped(.sys_access);
const cast = std.zig.c_translation.cast;

fn sys_access(self: *Process, pathname_ptr: UserCString, mode: u32) !void {
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    // Deny if file doesn't exist, or if asking for W_OK or X_OK. We only
    // allow R_OK and F_OK
    if (!fs.file_manager.exists(pathname))
        return error.PermissionDenied;
    if ((mode & linux.W_OK != 0) or (mode & linux.X_OK != 0)) {
        log.warn("denying {s}, mode {}\n", .{ pathname, mode });
        return error.PermissionDenied;
    }
}

pub fn handle_sys_access(self: *Process, arg0: usize, arg1: usize) !usize {
    const pathname_ptr = try UserCString.fromFlat(arg0);
    const mode = cast(u32, arg1);
    try sys_access(self, pathname_ptr, mode);
    return 0;
}
