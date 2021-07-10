usingnamespace @import("common.zig");
const fs = @import("fs/fs.zig");
const mem = @import("mem/mem.zig");
const linux = @import("linux.zig");
const log = std.log.scoped(.process);
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;

const Process = struct {
    pid: pid_t,
    tgid: pid_t,
    space: mem.AddressSpace,

    files: std.AutoHashMap(pid_t, *fs.FileDescription),

    var next_pid: pid_t = 1234;

    const pid_t = linux.pid_t;
    const fd_t = linux.fd_t;
    // const FileDescriptorTable

    pub fn fromCurrent() Process {
        // TODO
        const pid = next_pid;
        next_pid += 1;
        return Process{
            .pid = pid,
            .tgid = pid,
            .space = {},
            // .
        };
    }

    pub fn sysRead(self: *Process, fd: fd_t, buf: UserPtr(*const u8), count: usize) isize {
        return if (self.files.get(fd)) |file_desc_ptr|
            file_desc_ptr.read(buf, count)
        else
            -linux.EBADF;
    }

    pub fn sysRead(self: *Process, fd: fd_t, buf: UserSlice([]const u8)) isize {
        return if (self.files.get(fd)) |file_desc_ptr|
            file_desc_ptr.read(buf)
        else
            -linux.EBADF;
    }

    pub fn handleSyscall(
        self: *Process,
        syscall: linux.SYS,
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
        arg5: usize,
    ) usize {
        // log.debug("")
        return switch (syscall) {
            .read => self.sysRead(arg0, UserSlice([]const u8).fromFlat(arg1, arg2)),
            else => panic("unhandled syscall: {}\n", .{syscall}),
        };
    }
};
