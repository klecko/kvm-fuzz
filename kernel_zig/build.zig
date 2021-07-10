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

    // Kernel executable build step
    const exe = b.addExecutable("kernel_zig", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.setOutputDir(b.fmt("{s}/bin", .{b.install_path}));
    exe.setLinkerScriptPath("./linker.ld");
    exe.addPackage(.{
        .name = "linux_std",
        .path = "/home/klecko/zig/lib/std/os/bits/linux.zig"
    });
    exe.code_model = .kernel;
    exe.single_threaded = true;
    exe.emit_docs = true;

    // Kernel build options
    exe.addBuildOption(bool, "enable_instruction_count", true);
    exe.addBuildOption(bool, "enable_guest_output", true);

    exe.install();

    // Format step
    const fmt_step = b.addFmt(&.{"src"});
    exe.step.dependOn(&fmt_step.step);

    // Run step
    const run_option = b.step("run", "Run the kernel in the hypervisor with a test binary");
    const run = b.addSystemCommand(&.{
        "../build/hypervisor/kvm-fuzz",
        "-k",
        exe.getOutputPath(),
        "--",
        "../test_bins/readelf-static",
        "-a",
        "input"
    });
    run.step.dependOn(&exe.step);
    run_option.dependOn(&run.step);
}
