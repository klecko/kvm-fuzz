#include "perf.h"
#include "x86/asm.h"

namespace Perf {

#ifdef ENABLE_INSTRUCTION_COUNT
void init() {
	// Set perfomance counter CTR0 (which counts number of instructions)
	// to only count when in user mode
	wrmsr(MSR_FIXED_CTR_CTRL, 2);

	// Enable CTR0
	wrmsr(MSR_PERF_GLOBAL_CTRL, 1ULL << 32);
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