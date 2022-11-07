#include "common.h"

static Vm default_vm() {
	Vm vm(8*1024*1024, "zig-out/bin/kernel", "zig-out/bin/test_hooks", {});
	return vm;
}

// Make sure kernel is compiled with build_options.instruction_count = .user
void perform_test(Vm& vm) {
	REQUIRE(vm.get_instructions_executed_and_reset() == 0);

	// This includes the instruction where the breakpoint was placed, which is
	// now int3.
	vm.run_until(addr(vm, 0xc), stats);
	REQUIRE(vm.get_instructions_executed_and_reset() == 7);
}

// Instruction count doesn't seem to work if we create more VMs. I have no idea
// why. It doesn't matter if we read the MSR FIXED_CTR0 from kernel or from the
// hypervisor, it is 0. MSRS FIXED_CTR_CTRL and PERF_GLOBAL_CTRL look good:
// 0x2 and 100000000. Maybe it's a KVM bug?
// This is why all tests but one are commented. In order to run a test,
// uncomment it and comment the rest.
TEST_CASE("inst count") {
	Vm vm = default_vm();
	perform_test(vm);

	// Vm vm2 = default_vm();
	// perform_test(vm2);
}

// TEST_CASE("inst count + singlestep") {
// 	Vm vm = default_vm();
// 	vm.run_until(addr(vm, 0), stats);
// 	REQUIRE(vm.get_instructions_executed_and_reset() == 1); // int3
// 	vm.single_step(stats);
// 	REQUIRE(vm.regs().rip == addr(vm, 3));
// 	REQUIRE(vm.get_instructions_executed_and_reset() == 1); // singlestep
// }

void dummy_hook(Vm& vm) {
	vm.regs().rax = 0xdeadbeef;
}

// TEST_CASE("inst_count + hook") {
// 	Vm vm = default_vm();
// 	vm.set_hook(addr(vm, 0x6), dummy_hook);
// 	perform_test(vm);
// }