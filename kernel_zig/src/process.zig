usingnamespace @import("common.zig");
const fs = @import("fs/fs.zig");
const mem = @import("mem/mem.zig");
const linux = @import("linux.zig");
const utils = @import("utils/utils.zig");
const hypercalls = @import("hypercalls.zig");
const x86 = @import("x86/x86.zig");
const log = std.log.scoped(.process);
const Allocator = std.mem.Allocator;
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;
const UserCString = mem.safe.UserCString;
const pid_t = linux.pid_t;
const fd_t = linux.fd_t;
const mode_t = linux.mode_t;
const off_t = linux.off_t;

/// Just a hash map from file descriptors to file descriptions, and a reference
/// counter
const FileDescriptorTable = struct {
    table: HashMap,

    ref: RefCounter,

    const HashMap = std.AutoHashMap(fd_t, *fs.FileDescription);
    const RefCounter = utils.RefCounter(FileDescriptorTable);

    fn destroy(ref: *RefCounter) void {
        const self = @fieldParentPtr(FileDescriptorTable, "ref", ref);

        // Unref every FileDescription in the table
        var iter = self.table.valueIterator();
        while (iter.next()) |desc_ptr| {
            desc_ptr.*.ref.unref();
        }

        // Deinit the table and free the object
        self.table.deinit();
        self.ref.allocator.destroy(self);
    }

    pub fn createDefault(allocator: *Allocator) !*FileDescriptorTable {
        // Allocate the file descriptor table and initialize it
        const ret = try allocator.create(FileDescriptorTable);
        errdefer allocator.destroy(ret);
        ret.* = FileDescriptorTable{
            .table = HashMap.init(allocator),
            .ref = RefCounter.init(allocator, destroy),
        };
        errdefer ret.table.deinit();

        // Open the standard files
        const stdin = try fs.file_manager.openStdin(allocator);
        errdefer stdin.ref.unref();
        const stdout = try fs.file_manager.openStdout(allocator);
        errdefer stdout.ref.unref();
        const stderr = try fs.file_manager.openStderr(allocator);
        errdefer stderr.ref.unref();

        // Insert the files in the table
        try ret.table.put(linux.STDIN_FILENO, stdin);
        try ret.table.put(linux.STDOUT_FILENO, stdout);
        try ret.table.put(linux.STDERR_FILENO, stderr);

        return ret;
    }
};

pub const Process = struct {
    allocator: *Allocator,

    pid: pid_t,

    tgid: pid_t,

    space: mem.AddressSpace,

    files: *FileDescriptorTable,

    elf_path: []u8,

    brk: usize,

    min_brk: usize,

    var next_pid: pid_t = 1234;

    pub fn initial(allocator: *Allocator, info: *const hypercalls.VmInfo) !Process {
        // TODO
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

    pub fn startUser(self: *Process, argv: [][*:0]const u8, info: *const hypercalls.VmInfo) !void {
        // Allocate stack
        const stack_top = mem.layout.user_stack - mem.layout.user_stack_size;
        const perms = .{ .read = true, .write = true };
        try self.space.mapRange(stack_top, mem.layout.user_stack_size, perms, .{});

        // Set it up
        const stack = try self.setupUserStack(@intToPtr([*]u8, mem.layout.user_stack), argv, info);

        // Jump to user code
        log.info("Jumping to user at 0x{x} with stack 0x{x}!\n", .{ info.user_entry, stack });
        self.jumpToUser(info.user_entry, stack);
    }

    const elf = std.elf;
    fn setupUserStack(self: *Process, stack_ptr: [*]u8, argv: [][*:0]const u8, info: *const hypercalls.VmInfo) !usize {
        var stack = stack_ptr;
        stack -= 16;
        std.mem.set(u8, stack[0..16], 0);

        // Random bytes for auxv
        stack -= 16;
        var i: u8 = 0;
        while (i < 16) : (i += 1) {
            stack[i] = i;
        }
        const random_bytes_addr = @ptrToInt(stack);

        // Platform for auxv
        const platfform_string = "x86_64";
        stack -= platfform_string.len + 1;
        std.mem.copy(u8, stack[0..platfform_string.len], platfform_string);
        stack[platfform_string.len] = 0;
        const platform_addr = @ptrToInt(stack);

        // Align stack
        stack = @intToPtr([*]u8, @ptrToInt(stack) & ~@as(usize, 0xF));

        // Write argv strings saving pointers to each arg
        const argv_addrs = try self.allocator.alloc(usize, argv.len);
        defer self.allocator.free(argv_addrs);
        for (argv) |arg, idx| {
            const arg_slice = std.mem.span(arg);
            stack -= arg_slice.len + 1;
            std.mem.copy(u8, stack[0..arg_slice.len], arg_slice);
            stack[arg_slice.len] = 0;
            argv_addrs[idx] = @ptrToInt(stack);
        }

        // TODO
        const environ = [_][*:0]const u8{
            "AAAA",
            "BBBB",
        };

        // Write environ strings saving pointer to each env
        const env_addrs = try self.allocator.alloc(usize, environ.len);
        defer self.allocator.free(env_addrs);
        for (environ) |env, idx| {
            const env_slice = std.mem.span(env);
            stack -= env_slice.len + 1;
            std.mem.copy(u8, stack[0..env_slice.len], env_slice);
            stack[env_slice.len] = 0;
            env_addrs[idx] = @ptrToInt(stack);
        }

        // Align stack
        stack = @intToPtr([*]u8, @ptrToInt(stack) & ~@as(usize, 0xF));
        if ((env_addrs.len + 1 + argv_addrs.len + 1) & 1 == 0) // not sure
            stack -= 8;

        // Setup auxv
        const auxv = [_]elf.Auxv{
            makeAuxv(elf.AT_PHDR, info.elf_load_addr + info.phinfo.e_phoff),
            makeAuxv(elf.AT_PHENT, info.phinfo.e_phentsize),
            makeAuxv(elf.AT_PHNUM, info.phinfo.e_phnum),
            makeAuxv(elf.AT_PAGESZ, std.mem.page_size),
            makeAuxv(elf.AT_BASE, info.interp_base),
            makeAuxv(elf.AT_FLAGS, 0),
            makeAuxv(elf.AT_ENTRY, info.elf_entry),
            makeAuxv(elf.AT_RANDOM, random_bytes_addr),
            makeAuxv(elf.AT_EXECFN, argv_addrs[0]),
            makeAuxv(elf.AT_PLATFORM, platform_addr),
            makeAuxv(elf.AT_SECURE, 0),
            makeAuxv(elf.AT_UID, 0),
            makeAuxv(elf.AT_EUID, 0),
            makeAuxv(elf.AT_GID, 0),
            makeAuxv(elf.AT_EGID, 0),
            makeAuxv(elf.AT_NULL, 0),
        };
        const auxv_bytes = std.mem.sliceAsBytes(&auxv);
        stack -= auxv_bytes.len;
        std.mem.copy(u8, stack[0..auxv_bytes.len], auxv_bytes);

        // Setup envp
        var stack_usize_ptr = @ptrCast([*]usize, @alignCast(@sizeOf(usize), stack));
        stack_usize_ptr -= env_addrs.len + 1;
        std.mem.copy(usize, stack_usize_ptr[0..env_addrs.len], env_addrs);
        stack_usize_ptr[env_addrs.len] = 0;

        // Setup auxv
        stack_usize_ptr -= argv_addrs.len + 1;
        std.mem.copy(usize, stack_usize_ptr[0..argv_addrs.len], argv_addrs);
        stack_usize_ptr[argv_addrs.len] = 0;

        // Setup argc
        stack_usize_ptr -= 1;
        stack_usize_ptr.* = argv.len;

        // Some debugging
        log.debug("ARGS:\n", .{});
        for (argv_addrs) |arg_addr, idx| {
            const arg_slice = std.mem.span(@intToPtr([*:0]const u8, arg_addr));
            log.debug("\t{}: {s}\n", .{ idx, arg_slice });
        }

        const stack_usize = @ptrToInt(stack_usize_ptr);
        assert(stack_usize & ~@as(usize, 0xF) == stack_usize);
        return stack_usize;
    }

    fn makeAuxv(auxv_type: usize, value: usize) std.elf.Auxv {
        return std.elf.Auxv{
            .a_type = auxv_type,
            .a_un = .{ .a_val = value },
        };
    }

    fn jumpToUser(self: *Process, entry: usize, stack: usize) void {
        asm volatile (
        // Set user stack, RIP and RFLAGS
            \\mov %[stack], %%rsp
            \\mov %[entry], %%rcx
            \\mov $0x202, %%r11

            // Clear every other register
            \\xor %%rax, %%rax
            \\xor %%rbx, %%rbx
            \\xor %%rdx, %%rdx
            \\xor %%rdi, %%rdi
            \\xor %%rsi, %%rsi
            \\xor %%rbp, %%rbp
            \\xor %%r8, %%r8
            \\xor %%r9, %%r9
            \\xor %%r10, %%r10
            \\xor %%r12, %%r12
            \\xor %%r13, %%r13
            \\xor %%r14, %%r14
            \\xor %%r15, %%r15

            // Jump to user
            \\sysretq
            :
            : [stack] "rax" (stack),
              [entry] "rbx" (entry)
        );
    }

    fn sys_read(self: *Process, fd: fd_t, buf: UserSlice([]u8)) isize {
        return if (self.files.table.get(fd)) |file_desc_ptr|
            file_desc_ptr.read(file_desc_ptr, buf)
        else
            -linux.EBADF;
    }

    fn sys_arch_prctl(self: *Process, code: i32, addr: usize) i32 {
        var ret: i32 = 0;
        switch (code) {
            linux.ARCH_SET_FS => x86.wrmsr(.FS_BASE, addr),
            linux.ARCH_SET_GS, linux.ARCH_GET_FS, linux.ARCH_GET_GS => TODO(),
            else => ret = -linux.EINVAL,
        }
        return ret;
    }

    fn sys_brk(self: *Process, addr: usize) usize {
        log.debug("brk: trying to set to 0x{x}, current is 0x{x}\n", .{ addr, self.brk });
        if (addr < self.min_brk)
            return self.brk;

        const brk_next_page = mem.alignPageForward(self.brk);
        const brk_cur_page = mem.alignPageBackward(self.brk);
        if (addr > brk_next_page) {
            // We have to allocate space
            const size = mem.alignPageForward(addr - brk_next_page);
            self.space.mapRange(brk_next_page, size, .{ .read = true, .write = true }, .{}) catch |err| switch (err) {
                error.OutOfMemory => return self.brk,
                error.NotUserRange => return self.brk, // range wrapped around
                error.AlreadyMapped => unreachable,
            };
        } else if (addr <= brk_cur_page) {
            // We have to free space
            const addr_next_page = mem.alignPageForward(addr);
            const size = brk_next_page - addr_next_page;
            self.space.unmapRange(addr_next_page, size) catch |err| switch (err) {
                error.NotMapped, error.NotUserRange => unreachable,
            };
        }

        log.debug("brk: set to 0x{x}\n", .{addr});
        self.brk = addr;
        return self.brk;
    }

    fn unameHelper(comptime string: []const u8) [64:0]u8 {
        const zeroed_padding = [_:0]u8{0} ** std.math.max(0, 64 - string.len);
        return @ptrCast(*const [string.len]u8, string.ptr).* ++ zeroed_padding;
    }
    fn sys_uname(self: *Process, uname_ptr: UserPtr(*linux.utsname)) i32 {
        comptime const uname = linux.utsname{
            .sysname = unameHelper("Linux"),
            .nodename = unameHelper("pep1t0"),
            .release = unameHelper("5.8.0-43-generic"),
            .version = unameHelper("#49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021"),
            .machine = unameHelper("x86_64"),
            .domainname = unameHelper("(none)"),
        };
        mem.safe.copyToUserSingle(linux.utsname, uname_ptr, &uname) catch return -linux.EFAULT;
        return 0;
    }

    fn sys_access(self: *Process, pathname_ptr: UserCString, mode: u32) i32 {
        const pathname = mem.safe.copyStringFromUser(self.allocator, pathname_ptr) catch |err| switch (err) {
            error.OutOfMemory => return -linux.ENOMEM,
            error.NotUserRange, error.Fault => return -linux.EFAULT,
        };
        defer self.allocator.free(pathname);
        if (!fs.file_manager.exists(pathname))
            return -linux.EACCESS;
        if ((mode & linux.W_OK) or (mode & linux.X_OK)) {
            log.warn("sys_access {}, mode {}, denying\n", .{ pathname, mode });
            return -linux.EACCESS;
        }
        // It's asking for R_OK or F_OK
        return 0;
    }

    fn availableFd(self: Process) fd_t {
        var fd: fd_t = 0;
        while (self.files.table.contains(fd)) {
            fd += 1;
        }
        return fd;
    }

    fn sys_openat(self: *Process, dirfd: fd_t, pathname_ptr: UserCString, flags: i32, mode: linux.mode_t) i32 {
        assert(dirfd == linux.AT_FDCWD);
        assert(flags & linux.O_WRONLY == 0 and flags & linux.O_RDWR == 0);

        // Get the pathname
        const pathname = mem.safe.copyStringFromUser(self.allocator, pathname_ptr) catch |err| switch (err) {
            error.OutOfMemory => return -linux.ENOMEM,
            error.NotUserRange, error.Fault => return -linux.EFAULT,
        };
        defer self.allocator.free(pathname);

        log.debug("opening file '{s}'\n", .{pathname});

        // Check if the file exists
        if (!fs.file_manager.exists(pathname)) {
            log.warn("attempt to open unknown file '{s}'\n", .{pathname});
            return -linux.ENOENT;
        }

        // Open it
        const fd = self.availableFd();
        const desc = fs.file_manager.open(self.allocator, pathname, flags) catch |err| switch (err) {
            error.OutOfMemory => return -linux.ENOMEM,
        };
        self.files.table.put(fd, desc) catch |err| switch (err) {
            error.OutOfMemory => {
                desc.ref.unref();
                return -linux.ENOMEM;
            },
        };

        return fd;
    }

    fn sys_close(self: *Process, fd: fd_t) i32 {
        if (self.files.table.fetchRemove(fd)) |kv| {
            kv.value.ref.unref();
            return 0;
        }
        return -linux.EBADF;
    }

    fn sys_dup(self: *Process, old_fd: fd_t) i32 {
        // Dup old_fd into the first available fd
        if (self.files.table.get(old_fd)) |desc| {
            const new_fd = self.availableFd();
            self.files.table.put(new_fd, desc.ref.ref());
            return new_fd;
        }
        return -linux.EBADF;
    }

    fn sys_dup2(self: *Process, old_fd: fd_t, new_fd: fd_t) i32 {
        if (old_fd == new_fd)
            return old_fd;

        if (self.files.table.get(old_fd)) |old_desc| {
            // Get the entry corresponding to new_fd and place old_desc there.
            // If it already existed, unref the desc first.
            const new_fd_entry = self.files.table.getOrPut(new_fd);
            if (new_fd_entry.found_existing) {
                new_fd_entry.value_ptr.ref.unref();
            }
            new_fd_entry.value_ptr.* = old_desc.ref.ref();
            return new_fd;
        }

        return -linux.EBADF;
    }

    fn sys_fstat(self: *Process, fd: fd_t, stat_ptr: UserPtr(*linux.stat)) i32 {
        if (self.files.table.get(fd)) |desc| {
            return desc.stat(desc, stat_ptr);
        }
        return -linux.EBADF;
    }

    fn sys_readlink(self: *Process, pathname_ptr: UserCString, buf: UserSlice([]u8)) isize {
        if (buf.len() == 0)
            return -linux.EINVAL;
        const pathname = mem.safe.copyStringFromUser(self.allocator, pathname_ptr) catch |err| switch (err) {
            error.OutOfMemory => return -linux.ENOMEM,
            error.NotUserRange, error.Fault => return -linux.EFAULT,
        };
        defer self.allocator.free(pathname);
        assert(std.mem.eql(u8, pathname, "/proc/self/exe"));

        // Write path. Readlink does not append a null byte to buf.
        const size = std.math.min(self.elf_path.len, buf.len());
        mem.safe.copyToUser(u8, buf, self.elf_path[0..size]) catch return -linux.EFAULT;
        return @intCast(isize, size);
    }

    fn sys_lseek(self: *Process, fd: fd_t, offset: off_t, whence: i32) off_t {
        if (self.files.table.get(fd)) |desc| {
            var ret: off_t = switch (whence) {
                linux.SEEK_SET => offset,
                linux.SEEK_CUR => @intCast(off_t, desc.offset) + offset,
                linux.SEEK_END => @intCast(off_t, desc.size()) + offset,
                else => TODO(),
            };
            if (ret < 0)
                return -linux.EINVAL;
            desc.offset = @intCast(usize, ret);
            return ret;
        }
        return -linux.EBADF;
    }

    fn protToMemPerms(prot: i32) mem.Perms {
        assert(prot & linux.PROT_GROWSDOWN == 0 and prot & linux.PROT_GROWSUP == 0);
        return mem.Perms{
            .read = (prot & linux.PROT_READ) != 0,
            .write = (prot & linux.PROT_WRITE) != 0,
            .exec = (prot & linux.PROT_EXEC) != 0,
        };
    }

    fn sys_mmap(
        self: *Process,
        addr: UserPtr(*u8),
        length: usize,
        prot: i32,
        flags: i32,
        fd: fd_t,
        offset: usize,
    ) usize {
        TODO();
        // log.debug("mmap(0x{x}, {}, 0x{x}, 0x{x}, {}, 0x{x}\n", .{ addr.flat(), length, prot, flags, fd, offset });

        // const supported_flags = linux.MAP_PRIVATE | linux.MAP_SHARED | linux.MAP_ANONYMOUS |
        //     linux.MAP_FIXED | linux.MAP_DENYWRITE | linux.MAP_STACK;
        // assert(flags & supported_flags == flags);

        // // Check given file descriptor is valid
        // if (fd != -1 and !self.files.table.contains(fd))
        //     return -linux.EBADF;

        // // We must return EINVAL if no length, and ENOMEM if length wraps
        // // TODO: currently we would panic if length wraps.
        // if (length == 0)
        //     return -linux.EINVAL;
        // const length_aligned = mem.alignPageForward(length);
        // if (length_aligned == 0)
        //     return -linux.ENOMEM;

        // const map_private = (flags & linux.MAP_PRIVATE) != 0;
        // const map_shared = (flags & linux.MAP_SHARED) != 0;
        // const map_anonymous = (flags & linux.MAP_ANONYMOUS) != 0;
        // const map_fixed = (flags & linux.MAP_FIXED) != 0;

        // // Shared and private: choose one
        // if (map_shared and map_private)
        //     return -linux.EINVAL;
        // if (!map_shared and !map_private)
        //     return -linux.EINVAL;

        // // If MAP_FIXED, addr can't be null or not aligned
        // if (map_fixed and (addr.isNull() or !mem.isPageAligned(addr.flat())))
        //     return -linux.EINVAL;

        // // Get permisions. If we're mapping a file, map it as writable first
        // // so we can write its contents.
        // var perms = protToMemPerms(prot);
        // if (fd != -1)
        //     perms.write = true;

        // const flags = mem.AddressSpace.MapFlags{
        //     .discardAlreadyMapped = map_fixed,
        //     .shared = map_shared,
        // };

        // self.space.mapRange(addr.flat(), length_aligned, perms, flags);
    }

    fn sys_mprotect(self: *Process, addr: usize, length: usize, prot: i32) i32 {
        if (!mem.isPageAligned(addr))
            return -linux.EINVAL;

        // TODO: wrapping
        const length_aligned = mem.alignPageForward(length);
        self.space.setRangePerms(addr, length_aligned, protToMemPerms(prot)) catch return -linux.EINVAL;
        return 0;
    }

    fn sys_stat(self: *Process, pathname_ptr: UserCString, stat_ptr: UserPtr(*linux.stat)) i32 {
        const pathname = mem.safe.copyStringFromUser(self.allocator, pathname_ptr) catch |err| switch (err) {
            error.OutOfMemory => return -linux.ENOMEM,
            error.NotUserRange, error.Fault => return -linux.EFAULT,
        };
        defer self.allocator.free(pathname);

        if (!fs.file_manager.exists(pathname))
            return -linux.ENOENT;

        return fs.file_manager.stat(pathname, stat_ptr);
    }

    fn sys_write(self: *Process, fd: fd_t, buf: UserSlice([]const u8)) isize {
        if (self.files.table.get(fd)) |desc| {
            return desc.write(desc, buf);
        }
        return -linux.EBADF;
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
        log.debug("--> syscall {s}\n", .{@tagName(syscall)});
        const ret = switch (syscall) {
            .arch_prctl => std.meta.cast(usize, self.sys_arch_prctl(std.meta.cast(i32, arg0), arg1)),
            .brk => self.sys_brk(arg0),
            .openat => std.meta.cast(usize, self.sys_openat(std.meta.cast(fd_t, arg0), UserCString.fromFlat(arg1), std.meta.cast(i32, arg2), std.meta.cast(mode_t, arg3))),
            .read => @bitCast(usize, self.sys_read(std.meta.cast(fd_t, arg0), UserSlice([]u8).fromFlat(arg1, arg2))),
            .write => @bitCast(usize, self.sys_write(std.meta.cast(fd_t, arg0), UserSlice([]const u8).fromFlat(arg1, arg2))),
            .lseek => @bitCast(usize, self.sys_lseek(std.meta.cast(fd_t, arg0), @bitCast(off_t, arg1), std.meta.cast(i32, arg2))),
            .stat => std.meta.cast(usize, self.sys_stat(UserCString.fromFlat(arg0), UserPtr(*linux.stat).fromFlat(arg1))),
            .fstat => std.meta.cast(usize, self.sys_fstat(std.meta.cast(fd_t, arg0), UserPtr(*linux.stat).fromFlat(arg1))),
            .close => std.meta.cast(usize, self.sys_close(std.meta.cast(fd_t, arg0))),
            .uname => std.meta.cast(usize, self.sys_uname(UserPtr(*linux.utsname).fromFlat(arg0))),
            .readlink => @bitCast(usize, self.sys_readlink(UserCString.fromFlat(arg0), UserSlice([]u8).fromFlat(arg1, arg2))),
            .mprotect => std.meta.cast(usize, self.sys_mprotect(arg0, arg1, std.meta.cast(i32, arg2))),
            .getuid, .getgid, .geteuid, .getegid => 0,
            .exit, .exit_group => hypercalls.endRun(.Exit, null),
            else => panic("unhandled syscall: {}\n", .{syscall}),
        };
        log.debug("<-- syscall {s} returned 0x{x}\n", .{ @tagName(syscall), ret });
        return ret;
    }
};
