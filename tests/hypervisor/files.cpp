#include "common.h"

static Vm default_vm() {
	Vm vm(8*1024*1024, "zig-out/bin/kernel", "zig-out/bin/test_files", {});
	return vm;
}

TEST_CASE("files") {
	Vm vm = default_vm();
	vm.read_and_set_shared_file("./tests/input_hello_world");

	vaddr_t addr = vm.elf().resolve_symbol("test_me");
	REQUIRE(addr != 0);

	vm.run_until(addr, stats);

	char buf[6];
	vm.mmu().read_mem(buf, vm.regs().rdi, sizeof(buf));
	REQUIRE(strcmp(buf, "hello") == 0);

	std::string s = vm.mmu().read_string(vm.regs().rdi);
	REQUIRE(s == "hello");
}

