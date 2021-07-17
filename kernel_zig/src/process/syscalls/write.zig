usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const hypercalls = @import("../../hypercalls.zig");
const UserSlice = mem.safe.UserSlice;

fn sys_write(self: *Process, fd: linux.fd_t, buf: UserSlice([]const u8)) !usize {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    return file.write(file, buf);
}

pub fn handle_sys_write(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    const buf = try UserSlice([]const u8).fromFlat(arg1, arg2);
    return sys_write(self, fd, buf);
}

fn sys_writev(self: *Process, fd: linux.fd_t, iov_buf: UserSlice([]const linux.iovec)) !usize {
    const file = self.files.table.get(fd) orelse return error.BadFD;
    var ret: usize = 0;
    var i: usize = 0;
    var iov: linux.iovec = undefined;
    while (i < iov_buf.len()) : (i += 1) {
        // Get the iovec and write it
        try mem.safe.copyFromUserSingle(linux.iovec, &iov, iov_buf.ptrAt(i));
        const user_slice = UserSlice([]const u8).fromSlice(iov.iov_base[0..iov.iov_len]);
        ret += try file.write(file, user_slice);

        // If writing to stderr, assume this is an assertion failed, and report
        // it as crash
        if (fd == linux.STDERR_FILENO) {
            const fault = hypercalls.FaultInfo{
                .fault_type = .AssertionFailed,
                .rip = 0, // TODO
                .fault_addr = 0,
                .kernel = false,
            };
            hypercalls.endRun(.Crash, &fault);
        }
    }
    return ret;
}

pub fn handle_sys_writev(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const fd = std.meta.cast(linux.fd_t, arg0);
    if (std.meta.cast(i32, arg2) < 0)
        return error.InvalidArgument;
    const iov_buf = try UserSlice([]const linux.iovec).fromFlat(arg1, arg2);
    return sys_writev(self, fd, iov_buf);
}
