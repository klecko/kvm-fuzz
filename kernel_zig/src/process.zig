usingnamespace @import("common.zig");
const fs = @import("fs/fs.zig");
const mem = @import("mem/mem.zig");
const linux = @import("linux.zig");
const utils = @import("utils/utils.zig");
const hypercalls = @import("hypercalls.zig");
const log = std.log.scoped(.process);
const Allocator = std.mem.Allocator;
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;
const pid_t = linux.pid_t;
const fd_t = linux.fd_t;

/// Just a hash map from file descriptors to file descriptions, and a reference
/// counter
const FileDescriptorTable = struct {
    table: HashMap,

    ref: RefCounter,

    const HashMap = std.AutoArrayHashMap(fd_t, *fs.FileDescription);
    const RefCounter = utils.RefCounter(FileDescriptorTable);

    pub fn createDefault(
        allocator: *Allocator,
    ) !*FileDescriptorTable {
        const ret = try allocator.create(FileDescriptorTable);
        ret.* = FileDescriptorTable{
            .table = HashMap.init(allocator),
            .ref = RefCounter.init(allocator, null),
        };
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
        log.info("Jumping to user at 0x{x}!\n", .{info.user_entry});
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

    // pub fn sysRead(self: *Process, fd: fd_t, buf: UserPtr(*const u8), count: usize) isize {
    //     return if (self.files.get(fd)) |file_desc_ptr|
    //         file_desc_ptr.read(buf, count)
    //     else
    //         -linux.EBADF;
    // }

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
