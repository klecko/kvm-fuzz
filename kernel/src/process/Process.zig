const std = @import("std");
const common = @import("../common.zig");
const panic = common.panic;
const mem = @import("../mem/mem.zig");
const x86 = @import("../x86/x86.zig");
const linux = @import("../linux.zig");
const scheduler = @import("../scheduler.zig");
const hypercalls = @import("../hypercalls.zig");
const FileDescriptorTable = @import("FileDescriptorTable.zig");
const futex = @import("syscalls/futex.zig");
const robust_list = @import("syscalls/robust_list.zig");
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

space: *mem.AddressSpace,

files: *FileDescriptorTable,

elf_path: []const u8,

brk: usize,

min_brk: usize,

limits: Limits,

// Registers saved when scheduling
// TODO revisar
user_regs: UserRegs,

fs_base: usize,

blocked_signals: Sigset,

signal_handlers: *[linux._NSIG]Sigaction,

robust_list_head: ?mem.safe.UserPtr(*const linux.robust_list_head),

clear_child_tid_ptr: ?mem.safe.UserPtr(*i32),

// // Top of the stack
// kernel_rsp: usize,

// // Bottom of the stack, set in the TSS
// kernel_rsp0: usize,

var next_pid: linux.pid_t = 1234;

const Limits = @import("syscalls/prlimit.zig").Limits;

pub const UserRegs = x86.Regs;

pub const State = union(enum) {
    active,
    waiting: WaitInfo,
    futex: futex.Futex,
    exited: i32,
};

pub const WaitInfo = struct {
    pid: linux.pid_t,
    wstatus_ptr: ?mem.safe.UserPtr(*i32),
};

// This is different than linux.sigset_t, which seems to be the definition used by libc.
// The linux kernel uses simply a u64. We can do a bit better.
pub const Sigset = std.bit_set.IntegerBitSet(8 * 8);
comptime {
    std.debug.assert(@sizeOf(Sigset) == 8);
}

pub const Sigaction = extern struct {
    handler: ?*const fn (c_int) callconv(.C) void,
    flags: u64,
    restorer: ?*const fn () callconv(.C) void,
    mask: Sigset,
};

pub fn initial(allocator: Allocator, info: *const hypercalls.VmInfo) !Process {
    const elf_path_len = std.mem.indexOfScalar(u8, &info.elf_path, 0).?;
    const elf_path = try allocator.alloc(u8, elf_path_len);
    @memcpy(elf_path, info.elf_path[0..elf_path_len]);

    const signal_handlers = try allocator.create([linux._NSIG]Sigaction);
    signal_handlers.* = [_]Sigaction{.{
        .handler = linux.SIG.DFL,
        .flags = 0,
        .restorer = null,
        .mask = Process.Sigset.initEmpty(),
    }} ** linux._NSIG;

    const limits = Limits.default();
    const pid = getNextPid();

    return Process{
        .allocator = allocator,
        .pid = pid,
        .tgid = pid,
        .pgid = pid,
        .ptgid = 1,
        .state = .active,
        .space = try mem.AddressSpace.createFromCurrent(allocator),
        .files = try FileDescriptorTable.createDefault(allocator, limits.nofile.hard),
        .elf_path = elf_path,
        .brk = info.brk,
        .min_brk = info.brk,
        .limits = limits,
        // .kernel_rsp = 0,
        // .kernel_rsp0 = 0,
        .user_regs = undefined,
        .fs_base = undefined,
        .blocked_signals = Process.Sigset.initEmpty(),
        .signal_handlers = signal_handlers,
        .robust_list_head = null,
        .clear_child_tid_ptr = null,
    };
}

pub fn destroy(self: *Process) void {
    self.files.ref.unref();
    self.space.ref.unref();
    self.allocator.destroy(self);
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

pub const startUser = @import("user.zig").startUser;
pub const wakeRobustFutexes = robust_list.wakeRobustFutexes;

const handle_sys_arch_prctl = @import("syscalls/prctl.zig").handle_sys_arch_prctl;
const handle_sys_access = @import("syscalls/access.zig").handle_sys_access;
const handle_sys_brk = @import("syscalls/brk.zig").handle_sys_brk;
const handle_sys_openat = @import("syscalls/open.zig").handle_sys_openat;
const handle_sys_open = @import("syscalls/open.zig").handle_sys_open;
const handle_sys_close = @import("syscalls/open.zig").handle_sys_close;
const handle_sys_read = @import("syscalls/read.zig").handle_sys_read;
const handle_sys_pread64 = @import("syscalls/read.zig").handle_sys_pread64;
const handle_sys_write = @import("syscalls/write.zig").handle_sys_write;
const handle_sys_writev = @import("syscalls/write.zig").handle_sys_writev;
const handle_sys_sendfile = @import("syscalls/sendfile.zig").handle_sys_sendfile;
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
const handle_sys_gettimeofday = @import("syscalls/time.zig").handle_sys_gettimeofday;
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
const handle_sys_clone3 = @import("syscalls/clone.zig").handle_sys_clone3;
const handle_sys_exit = @import("syscalls/exit.zig").handle_sys_exit;
const handle_sys_exit_group = @import("syscalls/exit.zig").handle_sys_exit_group;
const handle_sys_wait4 = @import("syscalls/wait.zig").handle_sys_wait4;
const handle_sys_getpid = @import("syscalls/getpid.zig").handle_sys_getpid;
const handle_sys_gettid = @import("syscalls/getpid.zig").handle_sys_gettid;
const handle_sys_getppid = @import("syscalls/getpid.zig").handle_sys_getppid;
const handle_sys_getpgid = @import("syscalls/getpid.zig").handle_sys_getpgid;
const handle_sys_getrandom = @import("syscalls/random.zig").handle_sys_getrandom;
const handle_sys_tgkill = @import("syscalls/kill.zig").handle_sys_tgkill;
const handle_sys_futex = futex.handle_sys_futex;
const handle_sys_sched_getaffinity = @import("syscalls/sched.zig").handle_sys_sched_getaffinity;
const handle_sys_sched_yield = @import("syscalls/sched.zig").handle_sys_sched_yield;
const handle_sys_rt_sigaction = @import("syscalls/signals.zig").handle_sys_rt_sigaction;
const handle_sys_rt_sigprocmask = @import("syscalls/signals.zig").handle_sys_rt_sigprocmask;
const handle_sys_set_robust_list = robust_list.handle_sys_set_robust_list;

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
    log.debug("--> [{}] syscall {s} at {x}\n", .{ self.pid, @tagName(syscall), regs.rip });
    hypercalls.notifySyscallStart(syscall);
    defer hypercalls.notifySyscallEnd();

    // TODO singlestep issue
    // if (((regs.rflags >> 9) & 1) == 0)
    //     panic("lost flags :(\n", .{});

    // TODO define a syscall handler type that takes all arguments, and put
    // every handler into an array
    const ret = switch (syscall) {
        .arch_prctl => self.handle_sys_arch_prctl(arg0, arg1),
        .access => self.handle_sys_access(arg0, arg1),
        .brk => self.handle_sys_brk(arg0),
        .openat => self.handle_sys_openat(arg0, arg1, arg2, arg3),
        .open => self.handle_sys_open(arg0, arg1, arg2),
        .read => self.handle_sys_read(arg0, arg1, arg2),
        .pread64 => self.handle_sys_pread64(arg0, arg1, arg2, arg3),
        .write => self.handle_sys_write(arg0, arg1, arg2),
        .writev => self.handle_sys_writev(arg0, arg1, arg2),
        .sendfile => self.handle_sys_sendfile(arg0, arg1, arg2, arg3),
        .lseek => self.handle_sys_lseek(arg0, arg1, arg2),
        .stat => self.handle_sys_stat(arg0, arg1),
        .fstat => self.handle_sys_fstat(arg0, arg1),
        .fstatat64 => self.handle_sys_fstatat(arg0, arg1, arg2, arg3),
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
        .readlinkat => self.handle_sys_readlink(arg1, arg2, arg3),
        .mmap => self.handle_sys_mmap(arg0, arg1, arg2, arg3, arg4, arg5, regs),
        .mremap => error.OutOfMemory,
        .mprotect => self.handle_sys_mprotect(arg0, arg1, arg2),
        .munmap => self.handle_sys_munmap(arg0, arg1),
        .prlimit64 => self.handle_sys_prlimit(arg0, arg1, arg2, arg3),
        .time => self.handle_sys_time(arg0),
        .clock_gettime => self.handle_sys_clock_gettime(arg0, arg1),
        .gettimeofday => self.handle_sys_gettimeofday(arg0, arg1),
        .sysinfo => self.handle_sys_sysinfo(arg0),
        .fcntl => self.handle_sys_fcntl(arg0, arg1, arg2),
        .clone => self.handle_sys_clone(arg0, arg1, arg2, arg3, arg4, regs),
        .clone3 => self.handle_sys_clone3(arg0, arg1, regs),
        .wait4 => self.handle_sys_wait4(arg0, arg1, arg2, arg3, regs),
        .getpid => self.handle_sys_getpid(),
        .gettid => self.handle_sys_gettid(),
        .getppid => self.handle_sys_getppid(),
        .getpgid => self.handle_sys_getpgid(arg0),
        .getrandom => self.handle_sys_getrandom(arg0, arg1, arg2),
        .tgkill => self.handle_sys_tgkill(arg0, arg1, arg2, regs),
        .futex => self.handle_sys_futex(arg0, arg1, arg2, arg3, arg4, arg5, regs),
        .set_robust_list => self.handle_sys_set_robust_list(arg0, arg1),
        .sched_getaffinity => self.handle_sys_sched_getaffinity(arg0, arg1, arg2),
        .sched_yield => self.handle_sys_sched_yield(regs),
        .rt_sigaction => self.handle_sys_rt_sigaction(arg0, arg1, arg2, arg3),
        .rt_sigprocmask => self.handle_sys_rt_sigprocmask(arg0, arg1, arg2, arg3),
        .getuid, .getgid, .geteuid, .getegid => @as(usize, 1000),
        .set_tid_address,
        .sigaltstack,
        .setitimer,
        .madvise,
        .setsockopt,
        .fadvise64,
        .alarm,
        .ioctl,
        .seccomp,
        .prctl,
        .rseq,
        .pselect6,
        => blk: {
            // log.info("TODO {s}\n", .{@tagName(syscall)});
            break :blk @as(usize, 0);
        },
        .exit => self.handle_sys_exit(arg0, regs),
        .exit_group => self.handle_sys_exit_group(arg0, regs),
        else => {
            const stacktrace_regs = hypercalls.StackTraceRegs.from(regs);
            hypercalls.printStackTrace(&stacktrace_regs);
            panic("unhandled syscall: {s}\n", .{@tagName(syscall)});
        },
    } catch |err| linux.errorToErrno(err);

    // Small footgun here: we may have handled exit syscall. If this was not the
    // last process, we have switched to another process, this process has been
    // freed and the run continues. Therefore, we can't access self now. Instead,
    // use `scheduler.current()` to get the process we switched to.
    log.debug("<-- [{}] syscall {s} returned 0x{x}\n", .{ scheduler.current().pid, @tagName(syscall), ret });
    // if (syscall == .openat) {
    //     const stacktrace_regs = hypercalls.StackTraceRegs.from(regs);
    //     hypercalls.printStackTrace(&stacktrace_regs);
    // }
    return ret;
}
