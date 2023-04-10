#include <chrono>
#include "vm.h"

using namespace std;

void err(const char* msg) {
	puts(msg);
	exit(EXIT_FAILURE);
}

int main(int argc, char** argv) {
	if (argc != 2) err("args");
	int n = atoi(argv[1]);

	Vm vm(
		64*1024*1024,
		"zig-out/bin/kernel",
		"./zig-out/bin/resets_test",
		{"./zig-out/bin/resets_test", to_string(n)}
	);

	Stats dummy;
	vaddr_t start_addr = vm.elf().resolve_symbol("fuzz_start");
	vaddr_t end_addr = vm.elf().resolve_symbol("fuzz_end");
	if (!start_addr || !end_addr)
		err("no start addr or end addr\n");

	vm.run_until(start_addr, dummy);
	vm.set_breakpoint(end_addr);

	Stats stats;
	Vm runner(vm);
	auto start_time = chrono::steady_clock::now();
	chrono::duration<double> elapsed_time;
	do {
		for (int j = 0; j < 1000; j++) {
			Vm::RunEndReason r = runner.run(stats);
			assert(r == Vm::RunEndReason::Breakpoint);
			runner.reset(vm, stats);
			stats.cases++;
		}
		elapsed_time = chrono::steady_clock::now() - start_time;
	} while (elapsed_time.count() < 10);
	double fcps = (double)stats.cases / elapsed_time.count();
	double dirty = (double)stats.reset_pages / stats.cases;
	printf("[%d] fcps %lu, avg dirty %f\n", n, (size_t)fcps, dirty);
}