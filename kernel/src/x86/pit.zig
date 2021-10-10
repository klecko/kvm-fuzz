usingnamespace @import("../common.zig");
const x86 = @import("x86.zig");

// PIT runs at 1.193182 MHz, which means it's decremented 1193182 times
// per second.
const PIT_RATE = 1193182;

pub fn configureSleep(comptime microsecs: u64) void {
    // Make sure we won't overflow when calculating `value`
    const max_microsecs = std.math.maxInt(u16) * 1_000_000 / PIT_RATE;
    comptime assert(microsecs <= max_microsecs);

    // The value we'll write to channel 2
    const value: u16 = @intCast(u16, microsecs * PIT_RATE / 1_000_000);

    // Set input
    x86.outb(0x61, x86.inb(0x61) | 1);

    // Configure PIT
    const channel: u8 = 0b10 << 6; // channel 2
    const access_mode: u8 = 0b11 << 4; // low and high byte input mode
    const operating_mode: u8 = 0b001 << 1; // one-shot
    const binary_mode = 0b0;
    x86.outb(0x43, channel | access_mode | operating_mode | binary_mode);

    // Write value to channel 2
    x86.outb(0x42, @intCast(u8, value & 0xFF)); // low byte
    x86.outb(0x42, @intCast(u8, value >> 8)); // high byte
}

pub fn performSleep() void {
    // Clear input, set it, and wait until output is 0
    const mask = ~@intCast(u8, 1);
    x86.outb(0x61, x86.inb(0x61) & mask);
    x86.outb(0x61, x86.inb(0x61) | 1);
    while ((x86.inb(0x61) & 0x20) != 0) {}
}
