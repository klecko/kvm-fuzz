const std = @import("std");
const assert = std.debug.assert;
const Process = @import("../Process.zig");
const common = @import("../../common.zig");
const utils = @import("../../utils/utils.zig");
const panic = common.panic;
const linux = @import("../../linux.zig");
const mem = @import("../../mem/mem.zig");
const hypercalls = @import("../../hypercalls.zig");
const log = std.log.scoped(.sys_mmap);
const cast = std.zig.c_translation.cast;

fn protToMemPerms(prot: i32) mem.Perms {
    assert(prot & linux.PROT.GROWSDOWN == 0 and prot & linux.PROT.GROWSUP == 0);
    return mem.Perms{
        .read = (prot & linux.PROT.READ) != 0,
        .write = (prot & linux.PROT.WRITE) != 0,
        .exec = (prot & linux.PROT.EXEC) != 0,
    };
}

fn sys_mmap(
    self: *Process,
    addr: usize,
    length: usize,
    prot: i32,
    flags: linux.MAP,
    fd: linux.fd_t,
    offset: usize,
    regs: *Process.UserRegs,
) !usize {
    log.debug("mmap(0x{x}, {}, 0x{x}, 0x{x}, {}, 0x{x})\n", .{ addr, length, prot, @as(u32, @bitCast(flags)), fd, offset });

    // Check not implemented flags
    if (flags.TYPE == .SHARED_VALIDATE or flags.@"32BIT" or flags.GROWSDOWN or
        flags.LOCKED or flags.NONBLOCK or flags.HUGETLB or flags.SYNC or
        flags.FIXED_NOREPLACE)
    {
        log.warn("unsupported mmap flag: 0x{x}\n", .{@as(u32, @bitCast(flags))});
        return error.InvalidArgument;
    }

    // Check given file descriptor is valid. There's a TOCTOU vuln here, but we
    // don't have multithreading so who cares.
    if (!flags.ANONYMOUS and !self.files.table.contains(fd))
        return error.BadFD;

    // We must return EINVAL if no length, and ENOMEM if it overflows
    const length_aligned = mem.alignPageForwardChecked(length) catch return error.OutOfMemory;
    if (length_aligned == 0)
        return error.InvalidArgument;

    // If MAP_FIXED, addr can't be null or not aligned
    if (flags.FIXED and (addr == 0 or !mem.isPageAligned(addr)))
        return error.InvalidArgument;

    // Get permisions. If we're mapping a file, map it as writable first
    // so we can write its contents.
    var perms = protToMemPerms(prot);
    if (!flags.ANONYMOUS)
        perms.write = true;

    const map_flags = mem.AddressSpace.MapFlags{
        .discardAlreadyMapped = flags.FIXED,
        .shared = flags.TYPE == .SHARED,
    };

    // Perform mapping
    var ret: usize = undefined;
    var retry_anywhere: bool = false;
    if (addr != 0) {
        ret = addr;
        self.space.mapRange(addr, length_aligned, perms, map_flags) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.AlreadyMapped => {
                // The given range is already mapped. As MAP_FIXED is not set,
                // addr is just a hint, so try mapping anywhere.
                retry_anywhere = true;
            },
            error.NotUserRange => {
                // The given range is invalid. If MAP_FIXED is not set, try
                // mapping anywhere. Otherwise, we must return ENOMEM.
                if (!flags.FIXED) {
                    retry_anywhere = true;
                } else {
                    return error.OutOfMemory;
                }
            },
        };
    }
    if (addr == 0 or retry_anywhere) {
        // If we fail here that's a true ENOMEM.
        ret = try self.space.mapRangeAnywhere(length_aligned, perms, map_flags);
    }

    // If we are mapping a file, copy its content to memory
    if (!flags.ANONYMOUS) {
        const file = self.files.table.get(fd).?;
        assert(offset <= file.size()); // I don't know if this is possible TODO check it
        const copy_length = @min(file.size() - offset, length);
        @memcpy(@as([*]u8, @ptrFromInt(ret))[0..copy_length], file.buf[offset .. offset + copy_length]);

        // If it was read only, remove write permissions after copying content
        if (prot & linux.PROT.WRITE == 0) {
            perms.write = false;
            self.space.setRangePerms(ret, length_aligned, perms) catch unreachable;
        }

        // Check if we are being called from the interpreter and tell the hypervisor
        hypercalls.maybeLoadLibrary(ret, file.buf, regs.rip);
    }

    return ret;
}

pub fn handle_sys_mmap(
    self: *Process,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    regs: *Process.UserRegs,
) !usize {
    const addr = arg0;
    const length = arg1;
    const prot = cast(i32, arg2);
    // Zig defines linux.MAP, which uses the enum linux.MAP_TYPE for flags
    // MAP_SHARED and MAP_PRIVATE. Check it can actually be converted before
    // blindly cast it.
    _ = std.meta.intToEnum(linux.MAP_TYPE, arg3 & 0xF) catch return error.InvalidArgument;
    const flags: linux.MAP = @bitCast(@as(u32, @truncate(arg3)));
    const fd = cast(linux.fd_t, arg4);
    const offset = arg5;
    const ret = sys_mmap(self, addr, length, prot, flags, fd, offset, regs);
    if (ret == error.OutOfMemory) {
        log.warn("mmap returned ENOMEM when asking for {}\n", .{utils.fmtNumberAsMemory(length)});
    }
    return ret;
}

fn sys_munmap(self: *Process, addr: usize, length: usize) !void {
    const length_aligned = mem.alignPageForwardChecked(length) catch return error.InvalidArgument;
    if (!mem.isPageAligned(addr))
        return error.InvalidArgument;

    // Trying to munmap a not mapped range is not an error.
    self.space.unmapRange(addr, length_aligned) catch |err| switch (err) {
        error.NotMapped => {},
        error.NotUserRange => return error.InvalidArgument,
        error.OutOfMemory => return err,
    };
}

pub fn handle_sys_munmap(self: *Process, arg0: usize, arg1: usize) !usize {
    const addr = arg0;
    const length = arg1;
    try sys_munmap(self, addr, length);
    return 0;
}

fn sys_mprotect(self: *Process, addr: usize, length: usize, prot: i32) !void {
    const length_aligned = mem.alignPageForwardChecked(length) catch return error.InvalidArgument;
    if (!mem.isPageAligned(addr))
        return error.InvalidArgument;

    // mprotect returns ENOMEM if range is invalid or if any page is not mapped
    self.space.setRangePerms(addr, length_aligned, protToMemPerms(prot)) catch |err| switch (err) {
        error.NotMapped, error.NotUserRange => return error.OutOfMemory,
    };
}

pub fn handle_sys_mprotect(self: *Process, arg0: usize, arg1: usize, arg2: usize) !usize {
    const addr = arg0;
    const length = arg1;
    const prot = cast(i32, arg2);
    try sys_mprotect(self, addr, length, prot);
    return 0;
}
