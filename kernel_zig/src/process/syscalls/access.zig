usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserCString = mem.safe.UserCString;
const log = std.log.scoped(.sys_access);

fn sys_access(self: *Process, pathname_ptr: UserCString, mode: u32) !void {
    const pathname = try mem.safe.copyStringFromUser(self.allocator, pathname_ptr);
    defer self.allocator.free(pathname);

    // Deny if file doesn't exist, or if asking for W_OK or X_OK. We only
    // allow R_OK and F_OK
    if (!fs.file_manager.exists(pathname))
        return error.PermissionDenied;
    if ((mode & linux.W_OK) or (mode & linux.X_OK)) {
        log.warn("denying {}, mode {}\n", .{ pathname, mode });
        return error.PermissionDenied;
    }
}

pub fn handle_sys_access(self: *Process, arg0: usize, arg1: usize) !usize {
    const pathname_ptr = UserCString.fromFlat(arg0);
    const mode = std.meta.cast(u32, arg1);
    try sys_access(self, pathname_ptr, mode);
    return 0;
}
