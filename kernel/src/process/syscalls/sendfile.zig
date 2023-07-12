const std = @import("std");
const Process = @import("../Process.zig");
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;
const cast = std.zig.c_translation.cast;

fn sys_sendfile(
    self: *Process,
    out_fd: linux.fd_t,
    in_fd: linux.fd_t,
    offset_ptr: ?UserPtr(*linux.off_t),
    count: usize,
) !usize {
    const out_file = self.files.table.get(out_fd) orelse return error.BadFD;
    const in_file = self.files.table.get(in_fd) orelse return error.BadFD;
    if (!out_file.isWritable() or !in_file.isReadable())
        return error.BadFD;

    // Super hack: currently the file description API requires user buffers, and
    // can't read from or write to kernel space. Therefore, we need to allocate
    // a temporary buffer in user space.
    const count_aligned = mem.alignPageForward(count);
    const range_base = try self.space.mapRangeAnywhere(
        count_aligned,
        .{ .read = true, .write = true },
        .{},
    );
    defer self.space.unmapRange(range_base, count_aligned) catch {};
    const buf = UserSlice([]u8).fromFlat(range_base, count) catch unreachable;

    // Set offset if given
    const in_prev_offset = in_file.offset;
    if (offset_ptr) |ptr| {
        const offset = try mem.safe.copyFromUserSingle(linux.off_t, ptr.toConst());
        if (offset < 0) return error.InvalidArgument;
        in_file.offset = @intCast(usize, offset);
    }

    // Perform read and write operations
    const bytes_read = try in_file.read(buf);
    const ret = try out_file.write(buf.sliceTo(bytes_read).toConst());

    // Restore offset if needed
    if (offset_ptr) |ptr| {
        const offset = @intCast(linux.off_t, in_file.offset);
        try mem.safe.copyToUserSingle(linux.off_t, ptr, &offset);
        in_file.offset = in_prev_offset;
    }

    return ret;
}

pub fn handle_sys_sendfile(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) !usize {
    const out_fd = cast(linux.fd_t, arg0);
    const in_fd = cast(linux.fd_t, arg1);
    const offset_ptr = try UserPtr(*linux.off_t).fromFlatMaybeNull(arg2);
    const count = arg3;
    return sys_sendfile(self, out_fd, in_fd, offset_ptr, count);
}
