const std = @import("std");
const Target = std.Target;
const CrossTarget = std.zig.CrossTarget;

pub fn build(b: *std.build.Builder) void {
    const target = CrossTarget.parse(.{
        .arch_os_abi = "x86_64-freestanding-none",
        .cpu_features = "x86_64-mmx-sse-sse2+soft_float",
    }) catch unreachable;

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    // Kernel executable build step
    const exe = b.addExecutable("kernel", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.setOutputDir(b.install_path);
    exe.setLinkerScriptPath(.{ .path = "./linker.ld" });
    exe.code_model = .kernel;
    exe.single_threaded = true;
    exe.red_zone = false;

    // Kernel build options
    const build_options = b.addOptions();
    build_options.addOption(bool, "enable_instruction_count", true);
    build_options.addOption(bool, "enable_guest_output", true);
    exe.addOptions("build_options", build_options);

    exe.install();

    // Unit tests
    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(b.standardTargetOptions(.{}));
    exe_tests.setBuildMode(mode);
    exe_tests.addOptions("build_options", build_options);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);

    // Format step
    const fmt_step = b.addFmt(&.{"src"});
    exe.step.dependOn(&fmt_step.step);
}
