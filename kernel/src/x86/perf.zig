const std = @import("std");
const build_options = @import("build_options");
const hypercalls = @import("../hypercalls.zig");
const x86 = @import("x86.zig");
const log = std.log.scoped(.perf);

/// Time passed since the run started. If the VM runs until a certain point
/// before forking, hypervisor can reset this value so timer starts counting
/// from that point. Then, it will be resetted again when the VM memory is
/// resetted to the original state.
var current_timer: usize = 0;

/// Timeout value. If current_timer gets bigger than this value, the run will
/// end with reason Timeout. This value should be set by the hypervisor before
/// the VM is forked; otherwise it will be resetted to the origianl value when
/// the VM memory is resetted.
var timer_timeout: usize = std.math.maxInt(usize);

const CountMode = struct {
    const Kernel: usize = (1 << 0);
    const User: usize = (1 << 1);
    const All: usize = Kernel | User;
};

const IA32_FIXED_CTR0_ENABLE = 1 << 32;
const IA32_FIXED_CTR1_ENABLE = 1 << 33;
const IA32_FIXED_CTR2_ENABLE = 1 << 34;

fn initInstructionCount() void {
    const count_mode = switch (build_options.instruction_count) {
        .kernel => CountMode.Kernel,
        .user => CountMode.User,
        .all => CountMode.All,
        .none => return,
    };

    // Set performance counter CTR0 (which counts number of instructions) and
    // CTR1 (which counts number of cycles) to count when in given mode
    x86.wrmsr(.FIXED_CTR_CTRL, count_mode | (count_mode << 4));

    // Enable CTR0 and CTR1
    x86.wrmsr(.PERF_GLOBAL_CTRL, IA32_FIXED_CTR0_ENABLE | IA32_FIXED_CTR1_ENABLE);
}

pub fn init() void {
    initInstructionCount();

    hypercalls.submitTimeoutPointers(&current_timer, &timer_timeout);

    log.debug("Perf initialized\n", .{});
}

pub fn instructionsExecuted() usize {
    return if (build_options.instruction_count != .none) x86.rdmsr(.FIXED_CTR0) else 0;
}

pub fn tick() void {
    current_timer += x86.apic.TIMER_MICROSECS;
    if (current_timer > timer_timeout) {
        // Hypervisor doesn't reset the LAPIC, so we need to reset it ourselves.
        // If we don't, then the VM will be resetted but the timer won't
        // trigger ever again.
        x86.apic.resetTimer();
        hypercalls.endRun(.Timeout, null);
    }
}
