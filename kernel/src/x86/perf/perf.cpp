#include "perf.h"
#include "x86/asm.h"
#include "x86/apic/apic.h"

namespace Perf {

enum CountMode {
	Kernel = 1,
	User = 2,
};

// Hypervisor will write to these
// this may be resetted after each run?
static size_t g_timer = 0;
static size_t g_timeout_microsecs = -1;

void init() {
#ifdef ENABLE_INSTRUCTION_COUNT
	// Set perfomance counter CTR0 (which counts number of instructions)
	// to only count when in user mode
	wrmsr(MSR_FIXED_CTR_CTRL, CountMode::User);

	// Enable CTR0
	wrmsr(MSR_PERF_GLOBAL_CTRL, 1ULL << 32);
#endif

	hc_submit_timeout_pointers(&g_timer, &g_timeout_microsecs);

	dbgprintf("Perf initialized\n");
}

size_t instructions_executed() {
#ifdef ENABLE_INSTRUCTION_COUNT
	return rdmsr(MSR_FIXED_CTR0);
#else
	return 0;
#endif
}

void tick() {
	g_timer += APIC::timer_microsecs();
	if (g_timer >= g_timeout_microsecs) {
		// Hypervisor doesn't reset the LAPIC, so we need to reset it ourselves.
		// If we don't, then the VM will be resetted but the timer won't
		// trigger ever again.
		APIC::reset_timer();
		hc_end_run(RunEndReason::Timeout, nullptr);
	}
}

}