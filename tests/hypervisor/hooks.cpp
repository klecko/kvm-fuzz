#include "common.h"

/*
0000000000201120 <_start>:
  201120:       48 31 c0                xor    rax,rax
  201123:       48 ff c0                inc    rax
  201126:       48 ff c0                inc    rax
  201129:       90                      nop
  20112a:       90                      nop
  20112b:       90                      nop
  20112c:       90                      nop
*/

void hook_handler(Vm& vm) {
	vm.regs().rax = UINT64_MAX;
}

static Vm default_vm() {
	Vm vm(8*1024*1024, "zig-out/bin/kernel", "zig-out/bin/test_hooks", {});
	vm.set_hook(addr(vm, 9), hook_handler);
	return vm;
}

TEST_CASE("run_until + hook") {
	Vm vm = default_vm();

	vm.run_until(addr(vm, 9), stats);
	REQUIRE(vm.regs().rax == 2);

	vm.run_until(addr(vm, 0xc), stats);
	REQUIRE(vm.regs().rax == UINT64_MAX);
}

TEST_CASE("single step + hook") {
	Vm vm = default_vm();

	vm.run_until(addr(vm, 9), stats);
	REQUIRE(vm.regs().rax == 2);

	vm.single_step(stats);
	REQUIRE(vm.regs().rip == addr(vm, 0xa));
	REQUIRE(vm.regs().rax == UINT64_MAX);
}

TEST_CASE("breakpoint + single_step + hook") {
	Vm vm = default_vm();
	vm.run_until(addr(vm, 9), stats);
	vm.set_breakpoint(addr(vm, 9));
	REQUIRE(vm.regs().rip == addr(vm, 9));
	REQUIRE(vm.regs().rax == 2);

	// Make sure both single_step and run handle the breakpoint
	Vm::RunEndReason reason;
	reason = vm.run(stats);
	REQUIRE(reason == Vm::RunEndReason::Breakpoint);
	REQUIRE(vm.regs().rip == addr(vm, 9));

	reason = vm.single_step(stats);
	REQUIRE(reason == Vm::RunEndReason::Breakpoint);
	REQUIRE(vm.regs().rip == addr(vm, 9));

	vm.remove_breakpoint(addr(vm, 9));

	reason = vm.single_step(stats);
	REQUIRE(reason == Vm::RunEndReason::Debug);
	REQUIRE(vm.regs().rip == addr(vm, 0xa));
	REQUIRE(vm.regs().rax == UINT64_MAX);
}

TEST_CASE("hook + breakpoint") {
	Vm vm = default_vm();
	vm.set_breakpoint(addr(vm, 0xa));
	vm.run(stats);
	REQUIRE(vm.regs().rip == addr(vm, 0xa));
	REQUIRE(vm.regs().rax == UINT64_MAX);
}

TEST_CASE("hook after hook") {
	Vm vm = default_vm();
	vm.set_hook(addr(vm, 0xa), [](Vm& vm) {
		vm.regs().rbx = 0xdeadbeef;
	});
	vm.run_until(addr(vm, 0xC), stats);
	REQUIRE(vm.regs().rax == UINT64_MAX);
	REQUIRE(vm.regs().rbx == 0xdeadbeef);
}

TEST_CASE("hook changes rip") {
	Vm vm = default_vm();
	vm.run_until(addr(vm, 0), stats);

	vm.set_hook(addr(vm, 3), [](Vm& vm) {
		vm.regs().rbx = 0xdeadbeef;
		vm.regs().rip = addr(vm, 0xa);
	});

	vm.run_until(addr(vm, 0xC), stats);
	REQUIRE(vm.regs().rbx == 0xdeadbeef);
	REQUIRE(vm.regs().rax == 0);
}
