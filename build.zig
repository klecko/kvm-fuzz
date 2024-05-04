const std = @import("std");
const NativeTargetInfo = std.zig.system.NativeTargetInfo;

fn shouldStrip(mode: std.builtin.OptimizeMode) bool {
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
    b: *std.Build,
    std_target: std.Build.ResolvedTarget,
    std_optimize: std.builtin.OptimizeMode,
    shared_options: SharedOptions,
) void {
    // Custom x86_64 freestanding target for the kernel
    const target = std.Target.Query.parse(.{
        .arch_os_abi = "x86_64-freestanding-none",
        .cpu_features = "x86_64-mmx-sse-sse2+soft_float",
    }) catch unreachable;

    // Kernel executable build step
    const exe = b.addExecutable(.{
        .name = "kernel",
        .root_source_file = b.path("kernel/src/main.zig"),
        .target = std.Build.resolveTargetQuery(b, target),
        .optimize = std_optimize,
        .code_model = .kernel,
        .single_threaded = true,
        .strip = shouldStrip(std_optimize),
    });
    exe.setLinkerScript(b.path("kernel/linker.ld"));
    exe.entry = .{ .symbol_name = "kmain" };
    exe.root_module.red_zone = false;

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
    exe.root_module.addOptions("build_options", build_options);

    b.installArtifact(exe);

    // Unit tests
    const exe_tests = b.addTest(.{
        .root_source_file = b.path("kernel/src/main.zig"),
        .target = std_target,
        .optimize = std_optimize,
    });
    exe_tests.root_module.addOptions("build_options", build_options);
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_tests.step);

    // Format step
    const fmt_step = b.addFmt(.{ .paths = &.{"kernel/src"} });
    exe.step.dependOn(&fmt_step.step);
}

fn addHypervisorOptions(
    b: *std.Build,
    exe: *std.Build.Step.Compile,
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
    const kvm_dirty_log_ring_version_required = std.SemanticVersion{ .major = 5, .minor = 11, .patch = 0 };
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
        const linux_version_range = exe.rootModuleTarget().os.version_range.linux;
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
    b: *std.Build,
    std_target: std.Build.ResolvedTarget,
    std_optimize: std.builtin.OptimizeMode,
    shared_options: SharedOptions,
) void {
    const exe = b.addExecutable(.{
        .name = "kvm-fuzz",
        .target = std_target,
        .optimize = std_optimize,
        .strip = shouldStrip(std_optimize),
    });
    addHypervisorOptions(b, exe, shared_options);
    exe.addIncludePath(b.path("hypervisor/include"));
    exe.addCSourceFiles(.{
        .root = b.path("hypervisor/src"),
        .files = &.{
            "args.cpp",
            "corpus.cpp",
            "elf_debug.cpp",
            "elf_parser.cpp",
            "elfs.cpp",
            "files.cpp",
            "hypercalls.cpp",
            "main.cpp",
            "mutator.cpp",
            "mmu.cpp",
            "page_walker.cpp",
            "tracing.cpp",
            "utils.cpp",
            "vm.cpp",
        },
        .flags = &.{
            "-std=c++11",
            "-pthread",
            "-fno-exceptions",
            "-Wall",
        },
    });
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("dwarf");
    exe.linkSystemLibrary("elf");
    exe.linkSystemLibrary("crypto");

    b.installArtifact(exe);
}

fn buildSyscallsTests(b: *std.Build, std_target: std.Build.ResolvedTarget, std_optimize: std.builtin.OptimizeMode) void {
    // It would be great to link this binary statically. We'd need to link with
    // musl instead of glibc, but musl breaks tests. For example, musl implements
    // brk as `return -ENOMEM;` (https://www.openwall.com/lists/musl/2013/12/21/1).
    // Maybe the best would be that tests call syscalls directly, instead of
    // relying on the linked libc.

    // Use baseline cpu model so it doesn't generate AVX512 or other not supported
    // x86 extensions
    // var target = std_target.query;
    // target.cpu_model = .baseline;
    // target.setGnuLibCVersion(2, 34, 0); // workaround for libc.so.6 not being a symlink in ubuntu 21+

    const exe = b.addExecutable(.{
        .name = "syscalls_tests",
        .target = std_target, // TODO change with target
        .optimize = std_optimize,
        .strip = true,
    });
    exe.addIncludePath(b.path("tests"));
    exe.addCSourceFiles(.{
        .root = b.path("tests/syscalls"),
        .files = &.{
            "brk.cpp",
            "dup.cpp",
            "fcntl.cpp",
            "files.cpp",
            "fork.cpp",
            "getcwd.cpp",
            "main.cpp",
            "misc.cpp",
            "mmap.cpp",
            "readlink.cpp",
            "safe_mem.cpp",
            "sched.cpp",
            "socket.cpp",
            "stdin.cpp",
            "thread_local.cpp",
            "uname.cpp",
        },
        .flags = &.{
            "-std=c++11",
            "-Wall",
        },
    });
    exe.linkLibC();
    exe.linkLibCpp();

    const install = b.addInstallArtifact(exe, .{});
    const build_step = b.step("syscalls_tests", "Build syscalls tests");
    build_step.dependOn(&install.step);
}

fn buildHypervisorTests(b: *std.Build, std_target: std.Build.ResolvedTarget, std_optimize: std.builtin.OptimizeMode) void {
    const exe = b.addExecutable(.{
        .name = "hypervisor_tests",
        .target = std_target,
        .optimize = std_optimize,
    });
    exe.addIncludePath(b.path("tests"));
    exe.addIncludePath(b.path("hypervisor/include"));
    exe.addCSourceFiles(.{
        .files = &.{
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
        },
        .flags = &.{
            "-std=c++11",
        },
    });
    exe.defineCMacro("ENABLE_INSTRUCTION_COUNT", null);
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("dwarf");
    exe.linkSystemLibrary("elf");
    exe.linkSystemLibrary("crypto");

    const install = b.addInstallArtifact(exe, .{});
    const build_step = b.step("hypervisor_tests", "Build hypervisor tests");
    build_step.dependOn(&install.step);

    // Binaries needed for the tests
    const test_hooks_exe = b.addExecutable(.{
        .name = "test_hooks",
        .target = std_target,
    });
    test_hooks_exe.addAssemblyFile(b.path("tests/hypervisor/binaries/hooks.s"));
    const test_hooks_install = b.addInstallArtifact(test_hooks_exe, .{});
    install.step.dependOn(&test_hooks_install.step);

    const test_files_exe = b.addExecutable(.{
        .name = "test_files",
        .target = std_target,
    });
    test_files_exe.addCSourceFile(.{ .file = b.path("tests/hypervisor/binaries/files.c") });
    test_files_exe.linkLibC();
    const test_files_install = b.addInstallArtifact(test_files_exe, .{});
    install.step.dependOn(&test_files_install.step);
}

fn buildExperiments(b: *std.Build, std_target: std.Build.ResolvedTarget, std_optimize: std.builtin.OptimizeMode) void {
    const exe = b.addExecutable(.{
        .name = "resets_exp",
        .target = std_target,
        .optimize = std_optimize,
    });
    exe.addIncludePath(b.path("hypervisor/include"));
    exe.addCSourceFiles(.{
        .root = b.path("hypervisor"),
        .files = &.{
            "experiments/resets/resets_exp.cpp",
            "src/elf_debug.cpp",
            "src/elf_parser.cpp",
            "src/elfs.cpp",
            "src/files.cpp",
            "src/hypercalls.cpp",
            "src/mmu.cpp",
            "src/page_walker.cpp",
            "src/utils.cpp",
            "src/tracing.cpp",
            "src/vm.cpp",
        },
        .flags = &.{
            "-std=c++11",
        },
    });
    exe.defineCMacro("ENABLE_INSTRUCTION_COUNT", null);
    exe.linkLibC();
    exe.linkLibCpp();
    exe.linkSystemLibrary("dwarf");
    exe.linkSystemLibrary("elf");
    exe.linkSystemLibrary("crypto");
    const install = b.addInstallArtifact(exe, .{});
    const build_step = b.step("experiments", "Build experiments");
    build_step.dependOn(&install.step);

    const resets_test_exe = b.addExecutable(.{
        .name = "resets_test",
        .root_source_file = b.path("hypervisor/experiments/resets/resets_test.c"),
        .target = std_target,
    });
    resets_test_exe.linkLibC();
    const resets_test_install = b.addInstallArtifact(resets_test_exe, .{});
    install.step.dependOn(&resets_test_install.step);
}

pub fn build(b: *std.Build) void {
    const std_target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const std_optimize = b.standardOptimizeOption(.{});

    const shared_options = SharedOptions{
        .instruction_count = b.option(
            SharedOptions.InstructionCount,
            "instruction-count",
            "Instruction count mode. Default is user.",
        ) orelse .user,
    };

    buildKernel(b, std_target, std_optimize, shared_options);
    buildHypervisor(b, std_target, std_optimize, shared_options);
    buildSyscallsTests(b, std_target, std_optimize);
    buildHypervisorTests(b, std_target, std_optimize);
    buildExperiments(b, std_target, std_optimize);
}
