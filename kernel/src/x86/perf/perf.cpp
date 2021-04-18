#include "perf.h"
#include "x86/asm.h"

namespace Perf {

enum CountMode {
	Kernel = 1,
	User = 2,
};

#ifdef ENABLE_INSTRUCTION_COUNT
void init() {
	// Set perfomance counter CTR0 (which counts number of instructions)
	// to only count when in user mode
	wrmsr(MSR_FIXED_CTR_CTRL, CountMode::User);

	// Enable CTR0
	wrmsr(MSR_PERF_GLOBAL_CTRL, 1ULL << 32);

	dbgprintf("Perf initialized\n");
}

uint64_t instructions_executed() {
	return rdmsr(MSR_FIXED_CTR0);
}
#else
void init() {}
uint64_t instructions_executed() {
	return 0;
}
#endif

}