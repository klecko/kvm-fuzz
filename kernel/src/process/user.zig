const std = @import("std");
const assert = std.debug.assert;
const Process = @import("Process.zig");
const hypercalls = @import("../hypercalls.zig");
const mem = @import("../mem/mem.zig");
const elf = std.elf;
const log = std.log.scoped(.user);

pub fn startUser(
    self: *Process,
    argv: [][*:0]const u8,
    info: *const hypercalls.VmInfo,
) !void {
    // Allocate stack
    const stack_top = mem.layout.user_stack - mem.layout.user_stack_size;
    const perms = .{ .read = true, .write = true };
    try self.space.mapRange(stack_top, mem.layout.user_stack_size, perms, .{});

    // Set it up
    const stack_ptr = @intToPtr([*]u8, mem.layout.user_stack);
    const rsp = try setupUserStack(self, stack_ptr, argv, info);

    // Jump to user code
    log.info("Jumping to user at 0x{x} with rsp 0x{x}!\n", .{ info.user_entry, rsp });
    jumpToUser(info.user_entry, rsp);
}

fn setupUserStack(
    self: *Process,
    stack_ptr: [*]u8,
    argv: [][*:0]const u8,
    info: *const hypercalls.VmInfo,
) !usize {
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
        makeAuxv(elf.AT_SYSINFO_EHDR, 0x0),
        makeAuxv(elf.AT_PHDR, info.elf_load_addr + info.phinfo.e_phoff),
        makeAuxv(elf.AT_PHENT, info.phinfo.e_phentsize),
        makeAuxv(elf.AT_PHNUM, info.phinfo.e_phnum),
        makeAuxv(elf.AT_PAGESZ, std.mem.page_size),
        makeAuxv(elf.AT_BASE, info.interp_start),
        makeAuxv(elf.AT_FLAGS, 0),
        makeAuxv(elf.AT_ENTRY, info.elf_entry),
        makeAuxv(elf.AT_RANDOM, random_bytes_addr),
        makeAuxv(elf.AT_EXECFN, if (argv_addrs.len > 0) argv_addrs[0] else 0),
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
    stack_usize_ptr[0] = argv.len;

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

fn makeAuxv(auxv_type: usize, value: usize) elf.Auxv {
    return elf.Auxv{
        .a_type = auxv_type,
        .a_un = .{ .a_val = value },
    };
}

fn jumpToUser(entry: usize, rsp: usize) noreturn {
    asm volatile (
    // Set user stack, RIP and RFLAGS
        \\mov %[rsp], %%rsp
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
        : [rsp] "rax" (rsp),
          [entry] "rbx" (entry),
    );
    unreachable;
}
