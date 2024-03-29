const std = @import("std");
const CrossTarget = std.zig.CrossTarget;
const NativeTargetInfo = std.zig.system.NativeTargetInfo;

fn shouldStrip(mode: std.builtin.Mode) bool {
    return switch (mode) {
        .Debug, .ReleaseSafe => false,
        .ReleaseFast, .ReleaseSmall => true,
    };
}

const SharedOptions = struct {
    const InstructionCount = enum {
        kernel,
        user,
        all,
        none,
    };
    instruction_count: InstructionCount,
};

fn buildKernel(
    b: *std.build.Builder,
    std_target: CrossTarget,
    std_mode: std.builtin.Mode,
    shared_options: SharedOptions,
) void {
    // Custom x86_64 freestanding target for the kernel
    const target = CrossTarget.parse(.{
        .arch_os_abi = "x86_64-freestanding-none",
        .cpu_features = "x86_64-mmx-sse-sse2+soft_float",
    }) catch unreachable;

    // Kernel executable build step
    const exe = b.addExecutable("kernel", "kernel/src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(std_mode);
    exe.setLinkerScriptPath(.{ .path = "kernel/linker.ld" });
    exe.code_model = .kernel;
    exe.single_threaded = true;
    exe.red_zone = false;
    exe.strip = shouldStrip(exe.build_mode);

    // zig build options
    const enable_guest_output = b.option(
        bool,
        "enable-guest-output",
        "Enable guest output to stdout and stderr. Default is disabled.",
    ) orelse false;

    // Kernel build options
    const build_options = b.addOptions();
    build_options.addOption(
        SharedOptions.InstructionCount,
        "instruction_count",
        shared_options.instruction_count,
    );
    build_options.addOption(bool, "enable_guest_output", enable_guest_output);
    exe.addOptions("build_options", build_options);

    exe.install();

    // Unit tests
    const exe_tests = b.addTest("kernel/src/main.zig");
    exe_tests.setTarget(std_target);
    exe_tests.setBuildMode(std_mode);
    exe_tests.addOptions("build_options", build_options);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);

    // Format step
    const fmt_step = b.addFmt(&.{"kernel/src"});
    exe.step.dependOn(&fmt_step.step);
}

fn addHypervisorOptions(
    b: *std.build.Builder,
    exe: *std.build.LibExeObjStep,
    shared_options: SharedOptions,
) void {
    // Mutations
    const enable_mutations = b.option(
        bool,
        "enable-mutations",
        "Enable mutations. If disabled, inputs will be chosen from the initial " ++
            "corpus but they won't be mutated. Default is enabled.",
    ) orelse true;
    if (enable_mutations) {
        exe.defineCMacro("ENABLE_MUTATIONS", null);
    }

    // Coverage
    const Coverage = enum {
        breakpoints,
        intelpt,
        none,
    };
    const coverage = b.option(
        Coverage,
        "coverage",
        "Type of code-coverage used. Breakpoints provide basic block coverage " ++
            "only the first time the block is executed, while Intel PT provides " ++
            "edge coverage for every run. Default is breakpoints.",
    ) orelse .breakpoints;
    switch (coverage) {
        .breakpoints => exe.defineCMacro("ENABLE_COVERAGE_BREAKPOINTS", null),
        .intelpt => {
            exe.defineCMacro("ENABLE_COVERAGE_INTEL_PT", null);
            exe.linkSystemLibrary("xdc");
        },
        .none => {},
    }

    // Bitmap size
    const bitmap_size_str = b.option(
        []const u8,
        "bitmap-size",
        "Bitmap size used for Intel PT coverage. Default is 64K.",
    );
    // Check if option was given but coverage type is not Intel PT
    if (bitmap_size_str != null and coverage != .intelpt) {
        std.log.warn("option bitmap-size was specified but coverage type is {s}, ignoring", .{@tagName(coverage)});
    }
    if (coverage == .intelpt) {
        // Parse the string
        const size_str = bitmap_size_str orelse "64K";
        const number_len = std.mem.indexOfAny(u8, size_str, "KM") orelse size_str.len;
        const number = std.fmt.parseInt(usize, size_str[0..number_len], 0) catch @panic("error parsing bitmap-size");
        const size = if (number_len < size_str.len) switch (size_str[number_len]) {
            'K' => number * 1024,
            'M' => number * 1024 * 1024,
            else => unreachable,
        } else number;

        const size_str_parsed = std.fmt.allocPrint(b.allocator, "{}", .{size}) catch unreachable;
        defer b.allocator.free(size_str_parsed);
        exe.defineCMacro("COVERAGE_BITMAP_SIZE", size_str_parsed);
    }

    // Dirty log ring
    const kvm_dirty_log_ring_version_required = std.builtin.Version{ .major = 5, .minor = 11 };
    const enable_kvm_dirty_log_ring = b.option(
        bool,
        "enable-kvm-dirty-log-ring",
        std.fmt.comptimePrint(
            "Enable KVM dirty log ring, available from Linux {}. If disabled, " ++
                "the usual bitmap is used. Default is disabled.",
            .{kvm_dirty_log_ring_version_required},
        ),
    ) orelse false;
    if (enable_kvm_dirty_log_ring) {
        const linux_version_range = exe.target_info.target.os.version_range.linux;
        const version_ok = linux_version_range.isAtLeast(kvm_dirty_log_ring_version_required) orelse return;
        if (!version_ok) {
            std.log.warn(
                "Option enable_kvm_dirty_log_ring requires kernel >= {}, " ++
                    "current is {}. Compilation will continue but it will probably " ++
                    "fail at runtime.",
                .{ kvm_dirty_log_ring_version_required, linux_version_range.range.min },
            );
        }
        exe.defineCMacro("ENABLE_KVM_DIRTY_LOG_RING", null);
    }

    if (shared_options.instruction_count != .none) {
        exe.defineCMacro("ENABLE_INSTRUCTION_COUNT", null);
    }
}

fn buildHypervisor(
    b: *std.build.Builder,
    std_target: CrossTarget,
    std_mode: std.builtin.Mode,
    shared_options: SharedOptions,
) void {
    const exe = b.addExecutable("kvm-fuzz", null);
    exe.setTarget(std_target);
    exe.setBuildMode(std_mode);
    addHypervisorOptions(b, exe, shared_options);
    exe.addIncludePath("hypervisor/include");
    exe.addCSourceFiles(&.{
        "hypervisor/src/args.cpp",
        "hypervisor/src/corpus.cpp",
        "hypervisor/src/elf_debug.cpp",
        "hypervisor/src/elf_parser.cpp",
        "hypervisor/src/elfs.cpp",
        "hypervisor/src/files.cpp",
        "hypervisor/src/hypercalls.cpp",
        "hypervisor/src/main.cpp",
        "hypervisor/src/mutator.cpp",
        "hypervisor/src/mmu.cpp",
        "hypervisor/src/page_walker.cpp",
        "hypervisor/src/tracing.cpp",
        "hypervisor/src/utils.cpp",
        "hypervisor/src/vm.cpp",
    }, &.{
        "-std=c++11",
        "-pthread",
        "-fno-exceptions",
        "-Wall",
    });
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("dwarf");
    exe.linkSystemLibrary("elf");
    exe.linkSystemLibrary("crypto");
    exe.strip = shouldStrip(exe.build_mode);

    exe.install();
}

fn buildSyscallsTests(b: *std.build.Builder, std_target: CrossTarget, std_mode: std.builtin.Mode) void {
    const exe = b.addExecutable("syscalls_tests", null);

    // It would be great to link this binary statically. We'd need to link with
    // musl instead of glibc, but musl breaks tests. For example, musl implements
    // brk as `return -ENOMEM;` (https://www.openwall.com/lists/musl/2013/12/21/1).
    // Maybe the best would be that tests call syscalls directly, instead of
    // relying on the linked libc.

    // Use baseline cpu model so it doesn't generate AVX512 or other not supported
    // x86 extensions
    var target = std_target;
    target.cpu_model = .baseline;
    target.setGnuLibCVersion(2, 34, 0); // workaround for libc.so.6 not being a symlink in ubuntu 21+

    exe.setTarget(target);
    exe.setBuildMode(std_mode);
    exe.addIncludePath("./tests");
    exe.addCSourceFiles(&.{
        "tests/syscalls/brk.cpp",
        "tests/syscalls/dup.cpp",
        "tests/syscalls/fcntl.cpp",
        "tests/syscalls/files.cpp",
        "tests/syscalls/fork.cpp",
        "tests/syscalls/getcwd.cpp",
        "tests/syscalls/main.cpp",
        "tests/syscalls/misc.cpp",
        "tests/syscalls/mmap.cpp",
        "tests/syscalls/readlink.cpp",
        "tests/syscalls/safe_mem.cpp",
        "tests/syscalls/sched.cpp",
        "tests/syscalls/socket.cpp",
        "tests/syscalls/stdin.cpp",
        "tests/syscalls/thread_local.cpp",
        "tests/syscalls/uname.cpp",
    }, &.{
        "-std=c++11",
        "-Wall",
    });
    exe.linkLibC();
    exe.linkLibCpp();
    exe.strip = true;

    const install = b.addInstallArtifact(exe);
    const build_step = b.step("syscalls_tests", "Build syscalls tests");
    build_step.dependOn(&install.step);
}

fn buildHypervisorTests(b: *std.build.Builder, std_target: CrossTarget, std_mode: std.builtin.Mode) void {
    const exe = b.addExecutable("hypervisor_tests", null);

    exe.setTarget(std_target);
    exe.setBuildMode(std_mode);
    exe.addIncludePath("./tests");
    exe.addIncludePath("hypervisor/include");
    exe.addCSourceFiles(&.{
        "hypervisor/src/elf_debug.cpp",
        "hypervisor/src/elf_parser.cpp",
        "hypervisor/src/elfs.cpp",
        "hypervisor/src/files.cpp",
        "hypervisor/src/hypercalls.cpp",
        "hypervisor/src/mmu.cpp",
        "hypervisor/src/page_walker.cpp",
        "hypervisor/src/tracing.cpp",
        "hypervisor/src/utils.cpp",
        "hypervisor/src/vm.cpp",
        "tests/hypervisor/files.cpp",
        "tests/hypervisor/hooks.cpp",
        "tests/hypervisor/inst_count.cpp",
        "tests/hypervisor/main.cpp",
    }, &.{
        "-std=c++11",
    });
    exe.defineCMacro("ENABLE_INSTRUCTION_COUNT", null);
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("dwarf");
    exe.linkSystemLibrary("elf");
    exe.linkSystemLibrary("crypto");

    const install = b.addInstallArtifact(exe);
    const build_step = b.step("hypervisor_tests", "Build hypervisor tests");
    build_step.dependOn(&install.step);

    // Binaries needed for the tests
    const test_hooks_exe = b.addExecutable("test_hooks", "tests/hypervisor/binaries/hooks.s");
    const test_hooks_install = b.addInstallArtifact(test_hooks_exe);
    install.step.dependOn(&test_hooks_install.step);

    const test_files_exe = b.addExecutable("test_files", "tests/hypervisor/binaries/files.c");
    test_files_exe.linkLibC();
    const test_files_install = b.addInstallArtifact(test_files_exe);
    install.step.dependOn(&test_files_install.step);
}

fn buildExperiments(b: *std.build.Builder, std_target: CrossTarget, std_mode: std.builtin.Mode) void {
    const exe = b.addExecutable("resets_exp", null);
    exe.setTarget(std_target);
    exe.setBuildMode(std_mode);
    exe.addIncludePath("hypervisor/include");
    exe.addCSourceFiles(&.{
        "hypervisor/experiments/resets/resets_exp.cpp",
        "hypervisor/src/elf_debug.cpp",
        "hypervisor/src/elf_parser.cpp",
        "hypervisor/src/elfs.cpp",
        "hypervisor/src/files.cpp",
        "hypervisor/src/hypercalls.cpp",
        "hypervisor/src/mmu.cpp",
        "hypervisor/src/page_walker.cpp",
        "hypervisor/src/utils.cpp",
        "hypervisor/src/tracing.cpp",
        "hypervisor/src/vm.cpp",
    }, &.{
        "-std=c++11",
    });
    exe.defineCMacro("ENABLE_INSTRUCTION_COUNT", null);
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("dwarf");
    exe.linkSystemLibrary("elf");
    exe.linkSystemLibrary("crypto");
    const install = b.addInstallArtifact(exe);
    const build_step = b.step("experiments", "Build experiments");
    build_step.dependOn(&install.step);

    const resets_test_exe = b.addExecutable("resets_test", "hypervisor/experiments/resets/resets_test.c");
    resets_test_exe.linkLibC();
    const resets_test_install = b.addInstallArtifact(resets_test_exe);
    install.step.dependOn(&resets_test_install.step);
}

pub fn build(b: *std.build.Builder) void {
    const std_target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const std_mode = b.standardReleaseOptions();

    const shared_options = SharedOptions{
        .instruction_count = b.option(
            SharedOptions.InstructionCount,
            "instruction-count",
            "Instruction count mode. Default is user.",
        ) orelse .user,
    };

    buildKernel(b, std_target, std_mode, shared_options);
    buildHypervisor(b, std_target, std_mode, shared_options);
    buildSyscallsTests(b, std_target, std_mode);
    buildHypervisorTests(b, std_target, std_mode);
    buildExperiments(b, std_target, std_mode);
}
