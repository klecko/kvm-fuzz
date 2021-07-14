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
const handle_sys_access = @import("syscalls/access.zig").handle_sys_access;
const handle_sys_brk = @import("syscalls/brk.zig").handle_sys_brk;
const handle_sys_openat = @import("syscalls/open.zig").handle_sys_openat;
const handle_sys_close = @import("syscalls/open.zig").handle_sys_close;
const handle_sys_read = @import("syscalls/read.zig").handle_sys_read;
const handle_sys_pread64 = @import("syscalls/read.zig").handle_sys_pread64;
const handle_sys_write = @import("syscalls/write.zig").handle_sys_write;
const handle_sys_lseek = @import("syscalls/lseek.zig").handle_sys_lseek;
const handle_sys_stat = @import("syscalls/stat.zig").handle_sys_stat;
const handle_sys_fstat = @import("syscalls/stat.zig").handle_sys_fstat;
const handle_sys_uname = @import("syscalls/uname.zig").handle_sys_uname;
const handle_sys_readlink = @import("syscalls/readlink.zig").handle_sys_readlink;
const handle_sys_mmap = @import("syscalls/mmap.zig").handle_sys_mmap;
const handle_sys_munmap = @import("syscalls/mmap.zig").handle_sys_munmap;
const handle_sys_mprotect = @import("syscalls/mmap.zig").handle_sys_mprotect;
const handle_sys_prlimit = @import("syscalls/prlimit.zig").handle_sys_prlimit;
const handle_sys_clock_gettime = @import("syscalls/time.zig").handle_sys_clock_gettime;
const handle_sys_dup = @import("syscalls/dup.zig").handle_sys_dup;
const handle_sys_dup2 = @import("syscalls/dup.zig").handle_sys_dup2;
const handle_sys_getcwd = @import("syscalls/getcwd.zig").handle_sys_getcwd;
const handle_sys_chdir = @import("syscalls/getcwd.zig").handle_sys_chdir;
const handle_sys_socket = @import("syscalls/socket.zig").handle_sys_socket;
const handle_sys_bind = @import("syscalls/socket.zig").handle_sys_bind;
const handle_sys_listen = @import("syscalls/socket.zig").handle_sys_listen;
const handle_sys_accept = @import("syscalls/socket.zig").handle_sys_accept;

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
        .access => self.handle_sys_access(arg0, arg1),
        .brk => self.handle_sys_brk(arg0),
        .openat => self.handle_sys_openat(arg0, arg1, arg2, arg3),
        .read => self.handle_sys_read(arg0, arg1, arg2),
        .pread => self.handle_sys_pread64(arg0, arg1, arg2, arg3),
        .write => self.handle_sys_write(arg0, arg1, arg2),
        .lseek => self.handle_sys_lseek(arg0, arg1, arg2),
        .stat => self.handle_sys_stat(arg0, arg1),
        .fstat => self.handle_sys_fstat(arg0, arg1),
        .dup => self.handle_sys_dup(arg0),
        .dup2 => self.handle_sys_dup2(arg0, arg1),
        .socket => self.handle_sys_socket(arg0, arg1, arg2),
        .bind => self.handle_sys_bind(arg0, arg1, arg2),
        .listen => self.handle_sys_listen(arg0, arg1),
        .accept => self.handle_sys_accept(arg0, arg1, arg2),
        .close => self.handle_sys_close(arg0),
        .uname => self.handle_sys_uname(arg0),
        .getcwd => self.handle_sys_getcwd(arg0, arg1),
        .chdir => self.handle_sys_chdir(arg0),
        .readlink => self.handle_sys_readlink(arg0, arg1, arg2),
        .mmap => self.handle_sys_mmap(arg0, arg1, arg2, arg3, arg4, arg5),
        .mprotect => self.handle_sys_mprotect(arg0, arg1, arg2),
        .munmap => self.handle_sys_munmap(arg0, arg1),
        .prlimit64 => self.handle_sys_prlimit(arg0, arg1, arg2, arg3),
        .clock_gettime => self.handle_sys_clock_gettime(arg0, arg1),
        .getuid, .getgid, .geteuid, .getegid => @as(usize, 0),
        .set_tid_address, .set_robust_list, .rt_sigaction, .rt_sigprocmask, .futex, .sigaltstack, .setitimer => blk: {
            log.info("TODO {s}\n", .{@tagName(syscall)});
            break :blk @as(usize, 0);
        },
        .exit, .exit_group => hypercalls.endRun(.Exit, null),
        else => panic("unhandled syscall: {}\n", .{syscall}),
    } catch |err| linux.errorToErrno(err);

    log.debug("<-- syscall {s} returned 0x{x}\n", .{ @tagName(syscall), ret });
    return ret;
}
