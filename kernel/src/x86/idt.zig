const std = @import("std");
const assert = std.debug.assert;
const x86 = @import("x86.zig");
const interrupts = @import("../interrupts.zig");
const log = std.log.scoped(.idt);

const InterruptDescriptor = packed struct {
    offset_low: u16,
    selector: x86.gdt.SegmentSelector,
    ist: u3,
    zero0: u5 = 0,
    gate_type: GateType,
    zero1: u1 = 0,
    privilege: u2,
    present: u1,
    offset_mid: u16,
    offset_high: u32,
    zero2: u32 = 0,

    const GateType = enum(u4) {
        Task = 0b01011,
        Interrupt = 0b1110,
        Trap = 0b1111,
    };

    pub fn init(
        interrupt_handler: interrupts.InterruptHandlerEntryPoint,
        interrupt_stack: u3,
        gate_type: GateType,
    ) InterruptDescriptor {
        const offset = @intFromPtr(interrupt_handler);
        return InterruptDescriptor{
            .offset_low = @truncate(offset),
            .offset_mid = @truncate(offset >> 16),
            .offset_high = @truncate(offset >> 32),
            .selector = .KernelCode,
            .ist = interrupt_stack,
            .gate_type = gate_type,
            .privilege = 3,
            .present = 1,
        };
    }
};

pub const IDTPtr = packed struct {
    size: u16,
    offset: u64,
};

comptime {
    assert(@sizeOf(InterruptDescriptor) == 16);
}

/// Interrupt numbers associated with each exception.
/// https://wiki.osdev.org/Exceptions
pub const ExceptionNumber = struct {
    pub const DivByZero = 0;
    pub const Debug = 1;
    pub const NonMaskableInterrupt = 2;
    pub const Breakpoint = 3;
    pub const Overflow = 4;
    pub const BoundRangeExceeded = 5;
    pub const InvalidOpcode = 6;
    pub const DeviceNotAvailable = 7;
    pub const DoubleFault = 8;
    pub const InvalidTSS = 10;
    pub const SegmentNotPresent = 11;
    pub const StackSegmentFault = 12;
    pub const GeneralProtectionFault = 13;
    pub const PageFault = 14;
    pub const x87FloatingPointException = 16;
    pub const AlignmentCheck = 17;
    pub const MachineCheck = 18;
    pub const SIMDFloatingPointException = 19;
    pub const VirtualizationException = 20;
    pub const SecurityException = 30;

    pub fn string(number: usize) []const u8 {
        return switch (number) {
            DivByZero => "DivByZero",
            Debug => "Debug",
            NonMaskableInterrupt => "NonMaskableInterrupt",
            Breakpoint => "Breakpoint",
            Overflow => "Overflow",
            BoundRangeExceeded => "BoundRangeExceeded",
            InvalidOpcode => "InvalidOpcode",
            DeviceNotAvailable => "DeviceNotAvailable",
            DoubleFault => "DoubleFault",
            InvalidTSS => "InvalidTSS",
            SegmentNotPresent => "SegmentNotPresent",
            StackSegmentFault => "StackSegmentFault",
            GeneralProtectionFault => "GeneralProtectionFault",
            PageFault => "PageFault",
            x87FloatingPointException => "x87FloatingPointException",
            AlignmentCheck => "AlignmentCheck",
            MachineCheck => "MachineCheck",
            SIMDFloatingPointException => "SIMDFloatingPointException",
            VirtualizationException => "VirtualizationException",
            SecurityException => "SecurityException",
            else => "Unknown",
        };
    }
};

pub const IRQNumber = struct {
    pub const APICTimer = 32;
};

/// Number of IDT entries.
pub const N_IDT_ENTRIES = 256;

/// The entry point of every interrupt handler. This is where the CPU will jump
/// to when a given interrupt occurs.
const interrupt_handlers_entry_points = blk: {
    var tmp: [N_IDT_ENTRIES]interrupts.InterruptHandlerEntryPoint = undefined;
    for (&tmp, 0..) |*entry_point, i| {
        entry_point.* = interrupts.getInterruptHandlerEntryPoint(i);
    }
    break :blk tmp;
};

/// The IDT itself.
var idt: [N_IDT_ENTRIES]InterruptDescriptor = undefined;

pub fn init() void {
    // Initialize IDT
    for (&idt, 0..) |*entry, i| {
        const gate_type: InterruptDescriptor.GateType = if (i < 32) .Trap else .Interrupt;
        const interrupt_handler = interrupt_handlers_entry_points[i];
        const interrupt_stack = if (i == ExceptionNumber.DoubleFault) @as(u3, 1) else 0;
        entry.* = InterruptDescriptor.init(interrupt_handler, interrupt_stack, gate_type);
    }

    // Load IDT
    const idt_ptr = IDTPtr{
        .size = @sizeOf(@TypeOf(idt)) - 1,
        .offset = @intFromPtr(&idt),
    };
    x86.lidt(&idt_ptr);

    log.debug("IDT initialized\n", .{});
}
