pub usingnamespace @import("../common.zig");
const mem = @import("../mem/mem.zig");
const linux = @import("../linux.zig");
const hypercalls = @import("../hypercalls.zig");
const FileDescriptorTable = @import("FileDescriptorTable.zig");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.process);
const Process = @This();

allocator: *Allocator,

pid: linux.pid_t,

tgid: linux.pid_t,

space: mem.AddressSpace,

files: *FileDescriptorTable,

elf_path: []u8,

brk: usize,

min_brk: usize,

var next_pid: linux.pid_t = 1234;

pub fn initial(allocator: *Allocator, info: *const hypercalls.VmInfo) !Process {
    const elf_path_len = std.mem.indexOfScalar(u8, &info.elf_path, 0).?;
    const elf_path = try allocator.alloc(u8, elf_path_len);
    std.mem.copy(u8, elf_path, info.elf_path[0..elf_path_len]);

    const pid = next_pid;
    next_pid += 1;

    return Process{
        .allocator = allocator,
        .pid = pid,
        .tgid = pid,
        .space = mem.AddressSpace.fromCurrent(allocator),
        .files = try FileDescriptorTable.createDefault(allocator),
        .elf_path = elf_path,
        .brk = info.brk,
        .min_brk = info.brk,
    };
}

pub fn availableFd(self: Process) linux.fd_t {
    var fd: linux.fd_t = 0;
    while (self.files.table.contains(fd)) {
        fd += 1;
    }
    return fd;
}

const startUser = @import("user.zig").startUser;

const handle_sys_arch_prctl = @import("syscalls/prctl.zig").handle_sys_arch_prctl;
const handle_sys_brk = @import("syscalls/brk.zig").handle_sys_brk;
const handle_sys_openat = @import("syscalls/open.zig").handle_sys_openat;
const handle_sys_close = @import("syscalls/open.zig").handle_sys_close;
const handle_sys_read = @import("syscalls/read.zig").handle_sys_read;
const handle_sys_write = @import("syscalls/write.zig").handle_sys_write;
const handle_sys_lseek = @import("syscalls/lseek.zig").handle_sys_lseek;
const handle_sys_stat = @import("syscalls/stat.zig").handle_sys_stat;
const handle_sys_fstat = @import("syscalls/stat.zig").handle_sys_fstat;
const handle_sys_uname = @import("syscalls/uname.zig").handle_sys_uname;
const handle_sys_readlink = @import("syscalls/readlink.zig").handle_sys_readlink;
const handle_sys_mprotect = @import("syscalls/mmap.zig").handle_sys_mprotect;

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
    log.debug("--> syscall {s}\n", .{@tagName(syscall)});

    const ret = switch (syscall) {
        .arch_prctl => self.handle_sys_arch_prctl(arg0, arg1),
        .brk => self.handle_sys_brk(arg0),
        .openat => self.handle_sys_openat(arg0, arg1, arg2, arg3),
        .read => self.handle_sys_read(arg0, arg1, arg2),
        .write => self.handle_sys_write(arg0, arg1, arg2),
        .lseek => self.handle_sys_lseek(arg0, arg1, arg2),
        .stat => self.handle_sys_stat(arg0, arg1),
        .fstat => self.handle_sys_fstat(arg0, arg1),
        .close => self.handle_sys_close(arg0),
        .uname => self.handle_sys_uname(arg0),
        .readlink => self.handle_sys_readlink(arg0, arg1, arg2),
        .mprotect => self.handle_sys_mprotect(arg0, arg1, arg2),
        .getuid, .getgid, .geteuid, .getegid => @as(usize, 0),
        .exit, .exit_group => hypercalls.endRun(.Exit, null),
        else => panic("unhandled syscall: {}\n", .{syscall}),
    } catch |err| linux.errorToErrno(err);

    log.debug("<-- syscall {s} returned 0x{x}\n", .{ @tagName(syscall), ret });
    return ret;
}
