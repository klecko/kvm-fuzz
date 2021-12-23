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

    // Format step
    const fmt_step = b.addFmt(&.{"src"});
    exe.step.dependOn(&fmt_step.step);

    // Run step
    // const run_step = std.build.RunStep.create(b, "run");

    // run_step.addArtifactArg(exe);
    // const kvm_fuzz_path = b.pathJoin(&.{ exe.output_dir.?, "../hypervisor/kvm-fuzz"});
    // const kernel_path = b.pathJoin(&.{ exe.output_dir.?, exe.out_filename });
    // run_step.addArgs(&.{
    //     kvm_fuzz_path,
    //     "-k",
    //     kernel_path,
    //     "--single-run=/bin/ls",
    //     "--",
    // })

    // TODO take a look at exe.run()
    // const run_option = b.step("run", "Run the kernel in the hypervisor with a test binary");
    // const run = b.addSystemCommand(&.{
    //     "../build/hypervisor/kvm-fuzz",
    //     "-k",
    //     exe.getOutputPath(),
    //     "--single-run=../build/in/parallel",
    //     "--",
    //     "../test_bins/readelf-static",
    //     "-a",
    //     "input"
    // });
    // run.step.dependOn(&exe.step);
    // run_option.dependOn(&run.step);
}
