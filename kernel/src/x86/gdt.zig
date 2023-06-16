const std = @import("std");
const assert = std.debug.assert;
const x86 = @import("x86.zig");
const log = std.log.scoped(.gdt);

// https://wiki.osdev.org/Global_Descriptor_Table
const AccessBits = packed struct {
    /// Whether the segment has been accessed or not. Set to 1 by the CPU.
    accessed: u1,

    /// For code segments, whether read access is allowed.
    /// For data segments, whether write access is allowed.
    read_write: u1,

    /// For data segments, set if the segment grows down and unset if it grows up.
    /// For code segments, set if the segment can be executed from an equal or
    /// lower privilege level than the specified in `privilege`, and unset if
    /// it can only be executed from the ring set in `privilege`.
    dc: u1,

    /// Set for code segment, unset for data segment.
    executable: u1,

    /// Set for data and code segments, unset for Task State Segments.
    descriptor: u1,

    /// Descriptor Privilege Level of the segment.
    privilege: u2,

    /// Set for all valid segments.
    present: u1,
};

const FlagsBits = packed struct {
    /// Reserved as zero.
    zero: u1 = 0,

    /// Set for x86-64 code segment. Reserved for data segments.
    long: u1,

    /// Unset for 16 bit protected mode, set for 32 bit protected mode.
    /// It must be unset if `long` is set.
    size: u1,

    /// Unset if the limit unit in the descriptor is a byte, set if it's a page.
    granularity: u1,
};

/// The usual GDT entry
const GlobalDescriptor = packed struct {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: AccessBits,
    limit_high: u4,
    flags: FlagsBits,
    base_high: u8,

    const Type = enum {
        data,
        code,
    };

    fn init_base(base: u32, limit: u20, access: AccessBits, flags: FlagsBits) GlobalDescriptor {
        return GlobalDescriptor{
            .base_low = @intCast(u16, base & 0xFFFF),
            .base_mid = @intCast(u8, (base >> 16) & 0xFF),
            .base_high = @intCast(u8, base >> 24),
            .limit_low = @intCast(u16, limit & 0xFFFF),
            .limit_high = @intCast(u4, limit >> 16),
            .access = access,
            .flags = flags,
        };
    }

    pub fn init_null() GlobalDescriptor {
        return std.mem.zeroes(GlobalDescriptor);
    }

    pub fn init(comptime type_: Type, privilege: u2) GlobalDescriptor {
        const executable = if (type_ == .code) 1 else 0;
        const access = AccessBits{
            .accessed = 0,
            .read_write = 1,
            .dc = 0,
            .executable = executable,
            .descriptor = 1,
            .privilege = privilege,
            .present = 1,
        };
        const flags = FlagsBits{
            .long = executable,
            .size = 0,
            .granularity = 1,
        };
        return GlobalDescriptor.init_base(0, 0xFFFFF, access, flags);
    }
};

/// The GDT entry for the TSS
const TaskStateSegmentDescriptor = packed struct {
    descriptor: GlobalDescriptor,
    base_higher: u32,
    zero: u32 = 0,

    pub fn init(tss_ptr: *const TaskStateSegment) TaskStateSegmentDescriptor {
        const tss_ptr_flat = @ptrToInt(tss_ptr);
        const access = AccessBits{
            .accessed = 1,
            .read_write = 0,
            .dc = 0,
            .executable = 1,
            .descriptor = 0,
            .privilege = 0,
            .present = 1,
        };
        const flags = FlagsBits{
            .long = 0,
            .size = 0,
            .granularity = 0,
        };
        const descriptor = GlobalDescriptor.init_base(
            @intCast(u32, tss_ptr_flat & 0xFFFFFFFF),
            @sizeOf(TaskStateSegment),
            access,
            flags,
        );
        return TaskStateSegmentDescriptor{
            .descriptor = descriptor,
            .base_higher = @intCast(u32, tss_ptr_flat >> 32),
        };
    }
};

/// Stack used when an interrupt causes a change to ring zero. Set in the TSS.
var stack_rsp0: [0x2000]u8 align(std.mem.page_size) = undefined;

/// Stack used when handling interrupts like double faults, where the kernel
/// stack may be corrupted. Set in the TSS, and referenced by the `ist` field
/// in an Interrupt Descriptor.
var stack_ist1: [0x2000]u8 align(std.mem.page_size) = undefined;

/// TSS
const TaskStateSegment = packed struct {
    reserved1: u32 = 0,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved2: u64 = 0,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved3: u64 = 0,
    reserved4: u16 = 0,
    iopb: u16 = 104, //@sizeOf(TaskStateSegment),

    pub fn init() TaskStateSegment {
        var ret = std.mem.zeroes(TaskStateSegment);
        ret.rsp0 = @ptrToInt(&stack_rsp0) + stack_rsp0.len;
        ret.ist1 = @ptrToInt(&stack_ist1) + stack_ist1.len;
        return ret;
    }
};

/// The structure that points to the GDT. Size must set to the size of the GDT
/// minus 1, and offset must be its address. Used to load the GDT with asm.lgdt.
pub const GDTPtr = packed struct {
    size: u16,
    offset: u64,
};

// Make sure we didn't mess up the structs
comptime {
    assert(@sizeOf(GlobalDescriptor) == 0x08);
    assert(@sizeOf(TaskStateSegmentDescriptor) == 0x10);
    assert(@sizeOf(TaskStateSegment) == 104);
}

/// Our TSS, initialized at runtime.
pub var tss: TaskStateSegment = undefined;

const KernelPrivilegeLevel = 0;
const UserPrivigeLevel = 3;

/// Segment selectors, which represent offsets into the GDT for each segment.
pub const SegmentSelector = enum(u16) {
    Null = 0,
    KernelCode = 0x08 | KernelPrivilegeLevel,
    KernelData = 0x10 | KernelPrivilegeLevel,
    UserData = 0x18 | UserPrivigeLevel,
    UserCode = 0x20 | UserPrivigeLevel,
    TaskStateSegment = 0x28,
};

/// Number of GDT entries. TSS counts twice.
const N_GDT_ENTRIES = 7;

/// The GDT itself.
var gdt = blk: {
    var gdt_tmp: [N_GDT_ENTRIES]GlobalDescriptor = undefined;

    // Null descriptor
    gdt_tmp[0] = GlobalDescriptor.init_null();

    // Kernel code
    gdt_tmp[1] = GlobalDescriptor.init(.code, KernelPrivilegeLevel);

    // Kernel data
    gdt_tmp[2] = GlobalDescriptor.init(.data, KernelPrivilegeLevel);

    // User dada
    gdt_tmp[3] = GlobalDescriptor.init(.data, UserPrivigeLevel);

    // User code
    gdt_tmp[4] = GlobalDescriptor.init(.code, UserPrivigeLevel);

    // TSS descriptor is initialized at runtime
    break :blk gdt_tmp;
};

fn segmentIndex(selector: SegmentSelector) u16 {
    return @enumToInt(selector) / 8;
}

comptime {
    assert(segmentIndex(.Null) == 0);
    assert(segmentIndex(.KernelCode) == 1);
    assert(segmentIndex(.KernelData) == 2);
    assert(segmentIndex(.UserData) == 3);
    assert(segmentIndex(.UserCode) == 4);
    assert(segmentIndex(.TaskStateSegment) == 5);
}

pub fn init() void {
    // Initialize the TSS. This can't be done at comptime.
    tss = TaskStateSegment.init();

    // Create the TSS descriptor and add it to the GDT. The TSS has twice the
    // size of a normal GlobalDescriptor, so we have to bitcast and hack a bit.
    const tss_descriptor = TaskStateSegmentDescriptor.init(&tss);
    std.mem.copy(GlobalDescriptor, gdt[5..], @bitCast([2]GlobalDescriptor, tss_descriptor)[0..]);

    // Load the GDT.
    const gdt_ptr = GDTPtr{
        .size = @sizeOf(@TypeOf(gdt)) - 1,
        .offset = @ptrToInt(&gdt),
    };
    x86.lgdt(&gdt_ptr);

    // Load the Task Register.
    x86.ltr(.TaskStateSegment);

    log.debug("GDT initialized\n", .{});
}
