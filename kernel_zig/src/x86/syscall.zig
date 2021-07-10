usingnamespace @import("../common.zig");
const x86 = @import("x86.zig");
const SegmentSelector = x86.gdt.SegmentSelector;
const log = std.log.scoped(.syscall);

pub fn init() void {
    // SYSCALL instruction:
    //   CS.selector = STAR 47:32
    //   SS.selector = STAR 47:32 + 8
    // SYSRET instruction:
    //   CS.selector = STAR 63:48 + 16
    //   SS.selector = STAR 63:48 + 8
    comptime {
        assert(@enumToInt(SegmentSelector.KernelData) == @enumToInt(SegmentSelector.KernelCode) + 8);
        assert(@enumToInt(SegmentSelector.UserCode) == @enumToInt(SegmentSelector.UserData) + 8);
    }
    var star: usize = 0;
    star |= @as(usize, @enumToInt(SegmentSelector.KernelCode)) << 32; // for syscall
    star |= @as(usize, @enumToInt(SegmentSelector.UserData) - 8) << 48; // for sysret
    x86.wrmsr(.STAR, star);
    // x86.wrmsr(.LSTAR, syscall_entry);
    x86.wrmsr(.SYSCALL_MASK, 0x3F7DD5);

    log.debug("Syscall handler initialized\n", .{});
}
