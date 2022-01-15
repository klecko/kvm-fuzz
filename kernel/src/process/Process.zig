const std = @import("std");
const common = @import("../common.zig");
const panic = common.panic;
const mem = @import("../mem/mem.zig");
const x86 = @import("../x86/x86.zig");
const linux = @import("../linux.zig");
const hypercalls = @import("../hypercalls.zig");
const FileDescriptorTable = @import("FileDescriptorTable.zig");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.process);
const Process = @This();

allocator: Allocator,

// Unique for each process. Returned by gettid().
pid: linux.pid_t,

// Unique for each group of threads. Main thread has pid = tgid, other threads
// have same tgid but different pid. Returned by getpid().
tgid: linux.pid_t,

// Unique for each group of processes. Returned by getpgid().
pgid: linux.pid_t,

// Parent thread group id
ptgid: linux.pid_t,

state: State,

space: mem.AddressSpace,

files: *FileDescriptorTable,

elf_path: []const u8,

brk: usize,

min_brk: usize,

limits: Limits,

// Registers saved when scheduling
// TODO revisar
user_regs: UserRegs,

// // Top of the stack
// kernel_rsp: usize,

// // Bottom of the stack, set in the TSS
// kernel_rsp0: usize,

var next_pid: linux.pid_t = 1234;

const Limits = @import("syscalls/prlimit.zig").Limits;

pub const UserRegs = x86.Regs;

pub const State = union(enum) {
    active,
    waiting_for_any_with_pgid: linux.pid_t,
    waiting_for_tgid: linux.pid_t,
    waiting_for_any,
};

pub fn initial(allocator: Allocator, info: *const hypercalls.VmInfo) !Process {
    const elf_path_len = std.mem.indexOfScalar(u8, &info.elf_path, 0).?;
    const elf_path = try allocator.alloc(u8, elf_path_len);
    std.mem.copy(u8, elf_path, info.elf_path[0..elf_path_len]);

    const pid = getNextPid();

    const limits = Limits.default();
    return Process{
        .allocator = allocator,
        .pid = pid,
        .tgid = pid,
        .pgid = pid,
        .ptgid = 1,
        .state = .active,
        .space = mem.AddressSpace.fromCurrent(allocator),
        .files = try FileDescriptorTable.createDefault(allocator, limits.nofile.hard),
        .elf_path = elf_path,
        .brk = info.brk,
        .min_brk = info.brk,
        .limits = limits,
        // .kernel_rsp = 0,
        // .kernel_rsp0 = 0,
        .user_regs = undefined,
    };
}

pub fn getNextPid() linux.pid_t {
    // if (next_pid == std.math.maxInt(linux.pid_t))
    //     return null;
    const ret = next_pid;
    next_pid += 1;
    return ret;
}

pub fn availableFd(self: Process) ?linux.fd_t {
    return self.availableFdStartingOn(0);
}

pub fn availableFdStartingOn(self: Process, start: linux.fd_t) ?linux.fd_t {
    const fd_limit = self.limits.nofile.soft;
    var fd = start;
    while (fd < fd_limit) : (fd += 1) {
        if (!self.files.table.contains(fd))
            return fd;
    }
    return null;
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
const handle_sys_writev = @import("syscalls/write.zig").handle_sys_writev;
const handle_sys_lseek = @import("syscalls/lseek.zig").handle_sys_lseek;
const handle_sys_stat = @import("syscalls/stat.zig").handle_sys_stat;
const handle_sys_fstat = @import("syscalls/stat.zig").handle_sys_fstat;
const handle_sys_fstatat = @import("syscalls/stat.zig").handle_sys_fstatat;
const handle_sys_uname = @import("syscalls/uname.zig").handle_sys_uname;
const handle_sys_readlink = @import("syscalls/readlink.zig").handle_sys_readlink;
const handle_sys_mmap = @import("syscalls/mmap.zig").handle_sys_mmap;
const handle_sys_munmap = @import("syscalls/mmap.zig").handle_sys_munmap;
const handle_sys_mprotect = @import("syscalls/mmap.zig").handle_sys_mprotect;
const handle_sys_prlimit = @import("syscalls/prlimit.zig").handle_sys_prlimit;
const handle_sys_time = @import("syscalls/time.zig").handle_sys_time;
const handle_sys_clock_gettime = @import("syscalls/time.zig").handle_sys_clock_gettime;
const handle_sys_dup = @import("syscalls/dup.zig").handle_sys_dup;
const handle_sys_dup2 = @import("syscalls/dup.zig").handle_sys_dup2;
const handle_sys_getcwd = @import("syscalls/getcwd.zig").handle_sys_getcwd;
const handle_sys_chdir = @import("syscalls/getcwd.zig").handle_sys_chdir;
const handle_sys_socket = @import("syscalls/socket.zig").handle_sys_socket;
const handle_sys_bind = @import("syscalls/socket.zig").handle_sys_bind;
const handle_sys_listen = @import("syscalls/socket.zig").handle_sys_listen;
const handle_sys_accept = @import("syscalls/socket.zig").handle_sys_accept;
const handle_sys_recv = @import("syscalls/socket.zig").handle_sys_recv;
const handle_sys_recvfrom = @import("syscalls/socket.zig").handle_sys_recvfrom;
const handle_sys_sysinfo = @import("syscalls/sysinfo.zig").handle_sys_sysinfo;
const handle_sys_fcntl = @import("syscalls/fcntl.zig").handle_sys_fcntl;
const handle_sys_clone = @import("syscalls/clone.zig").handle_sys_clone;
const handle_sys_exit = @import("syscalls/exit.zig").handle_sys_exit;
const handle_sys_exit_group = @import("syscalls/exit.zig").handle_sys_exit_group;
const handle_sys_wait4 = @import("syscalls/wait.zig").handle_sys_wait4;
const handle_sys_getpid = @import("syscalls/getpid.zig").handle_sys_getpid;
const handle_sys_gettid = @import("syscalls/getpid.zig").handle_sys_gettid;
const handle_sys_getppid = @import("syscalls/getpid.zig").handle_sys_getppid;
const handle_sys_getpgid = @import("syscalls/getpid.zig").handle_sys_getpgid;
const handle_sys_tgkill = @import("syscalls/kill.zig").handle_sys_tgkill;
const handle_sys_futex = @import("syscalls/futex.zig").handle_sys_futex;

pub noinline fn handleSyscall(
    self: *Process,
    syscall: linux.SYS,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    regs: *UserRegs,
) usize {
    log.debug("--> [{}] syscall {s}\n", .{ self.pid, @tagName(syscall) });

    // TODO define a syscall handler type that takes all arguments, and put
    // every handler into an array
    const ret = switch (syscall) {
        .arch_prctl => self.handle_sys_arch_prctl(arg0, arg1),
        .access => self.handle_sys_access(arg0, arg1),
        .brk => self.handle_sys_brk(arg0),
        .openat => self.handle_sys_openat(arg0, arg1, arg2, arg3),
        .read => self.handle_sys_read(arg0, arg1, arg2),
        .pread => self.handle_sys_pread64(arg0, arg1, arg2, arg3),
        .write => self.handle_sys_write(arg0, arg1, arg2),
        .writev => self.handle_sys_writev(arg0, arg1, arg2),
        .lseek => self.handle_sys_lseek(arg0, arg1, arg2),
        .stat => self.handle_sys_stat(arg0, arg1),
        .fstat => self.handle_sys_fstat(arg0, arg1),
        .fstatat => self.handle_sys_fstatat(arg0, arg1, arg2, arg3),
        .dup => self.handle_sys_dup(arg0),
        .dup2 => self.handle_sys_dup2(arg0, arg1),
        .socket => self.handle_sys_socket(arg0, arg1, arg2),
        .bind => self.handle_sys_bind(arg0, arg1, arg2),
        .listen => self.handle_sys_listen(arg0, arg1),
        .accept => self.handle_sys_accept(arg0, arg1, arg2),
        // .recv => self.handle_sys_recv(arg0, arg1, arg2, arg3),
        .recvfrom => self.handle_sys_recvfrom(arg0, arg1, arg2, arg3, arg4, arg5),
        .close => self.handle_sys_close(arg0),
        .uname => self.handle_sys_uname(arg0),
        .getcwd => self.handle_sys_getcwd(arg0, arg1),
        .chdir => self.handle_sys_chdir(arg0),
        .readlink => self.handle_sys_readlink(arg0, arg1, arg2),
        .mmap => self.handle_sys_mmap(arg0, arg1, arg2, arg3, arg4, arg5),
        .mprotect => self.handle_sys_mprotect(arg0, arg1, arg2),
        .munmap => self.handle_sys_munmap(arg0, arg1),
        .prlimit64 => self.handle_sys_prlimit(arg0, arg1, arg2, arg3),
        .time => self.handle_sys_time(arg0),
        .clock_gettime => self.handle_sys_clock_gettime(arg0, arg1),
        .sysinfo => self.handle_sys_sysinfo(arg0),
        .fcntl => self.handle_sys_fcntl(arg0, arg1, arg2),
        .clone => self.handle_sys_clone(arg0, arg1, arg2, arg3, arg4, regs),
        .wait4 => self.handle_sys_wait4(arg0, arg1, arg2, arg3, regs),
        .getpid => self.handle_sys_getpid(),
        .gettid => self.handle_sys_gettid(),
        .getppid => self.handle_sys_getppid(),
        .getpgid => self.handle_sys_getpgid(arg0),
        .tgkill => self.handle_sys_tgkill(arg0, arg1, arg2, regs),
        .futex => self.handle_sys_futex(arg0, arg1, arg2, arg3, arg4, arg5),
        .getuid, .getgid, .geteuid, .getegid => @as(usize, 0),
        .set_tid_address,
        .set_robust_list,
        .rt_sigaction,
        .rt_sigprocmask,
        .sigaltstack,
        .setitimer,
        .madvise,
        .setsockopt,
        .sched_yield,
        => blk: {
            // log.info("TODO {s}\n", .{@tagName(syscall)});
            break :blk @as(usize, 0);
        },
        .exit => self.handle_sys_exit(arg0, regs),
        .exit_group => self.handle_sys_exit_group(arg0, regs),
        else => panic("unhandled syscall: {s}\n", .{@tagName(syscall)}),
    } catch |err| linux.errorToErrno(err);

    log.debug("<-- [{}] syscall {s} returned 0x{x}\n", .{ self.pid, @tagName(syscall), ret });
    return ret;
}
