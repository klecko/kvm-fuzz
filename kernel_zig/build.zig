const std = @import("std");
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;

pub fn build(b: *std.build.Builder) void {
    const target = CrossTarget.parse(.{
        .arch_os_abi = "x86_64-freestanding-none",
        .cpu_features = "x86_64-mmx-sse-sse2+soft_float"
    }) catch unreachable;

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const fmt_step = b.addFmt(&.{"src"});
    b.default_step.dependOn(&fmt_step.step);

    const exe = b.addExecutable("kernel_zig", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.setLinkerScriptPath("./linker.ld");
    exe.code_model = .kernel;
    exe.emit_docs = true;

    // Build options
    exe.addBuildOption(bool, "enable_instruction_count", true);

    exe.install();
}
