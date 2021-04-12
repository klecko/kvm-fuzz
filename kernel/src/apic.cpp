#include "apic.h"
#include "common.h"
#include "page_walker.h"
#include "asm.h"
#include "pit.h"

#define APIC_APICID     0x20
#define APIC_APICVER    0x30
#define APIC_TASKPRIOR  0x80
#define APIC_EOI        0x0B0
#define APIC_LDR        0x0D0
#define APIC_DFR        0x0E0
#define APIC_SPURIOUS   0x0F0
#define APIC_ESR        0x280
#define APIC_ICRL       0x300
#define APIC_ICRH       0x310
#define APIC_LVT_TMR    0x320
#define APIC_LVT_PERF   0x340
#define APIC_LVT_LINT0  0x350
#define APIC_LVT_LINT1  0x360
#define APIC_LVT_ERR    0x370
#define APIC_TMRINITCNT 0x380
#define APIC_TMRCURRCNT 0x390
#define APIC_TMRDIV     0x3E0
#define APIC_LAST       0x38F
#define APIC_DISABLE    0x10000
#define APIC_SW_ENABLE  0x100
#define APIC_CPUFOCUS   0x200
#define APIC_NMI        4<<8
#define TMR_PERIODIC    0x20000
#define TMR_BASEDIV     1<<20

namespace APIC {

static const uint64_t TIMER_MICROSECS = 1000;
static uint8_t* apic;
static uint32_t counter_value;

static void write_reg(uint16_t reg, uint32_t value) {
	*(volatile uint32_t*)(apic + reg) = value;
}

static uint32_t read_reg(uint16_t reg) {
	return *(volatile uint32_t*)(apic + reg);
}

void init() {
	// Get APIC phys address
	uintptr_t phys = rdmsr(MSR_APIC_BASE) & PTL1_MASK;

	// Map it
	apic = (uint8_t*)0x1234000; // FIXME: which address should i map it to?
	PageWalker mapper(apic, 0x1000);
	mapper.map(phys, PDE64_RW | PDE64_PRESENT);

	counter_value = 0xFFFFFFFF;

	// Initialize APIC
	write_reg(APIC_DFR, 0x0FFFFFFFF);
	write_reg(APIC_LDR, (read_reg(APIC_LDR) & 0x00FFFFFF) | 1);
	write_reg(APIC_LVT_TMR, APIC_DISABLE);
	write_reg(APIC_LVT_PERF, APIC_NMI);
	write_reg(APIC_LVT_LINT0, APIC_DISABLE);
	write_reg(APIC_LVT_LINT1, APIC_DISABLE);
	write_reg(APIC_TASKPRIOR, 0);

	// Enable APIC
	wrmsr(MSR_APIC_BASE, rdmsr(MSR_APIC_BASE) | (1 << 11));
	write_reg(APIC_SPURIOUS, 0xFF | APIC_SW_ENABLE);
	write_reg(APIC_LVT_TMR, 32); // one-shot mode
	write_reg(APIC_TMRDIV, 3);

	// Calculate the counter value we'll set.
	// We want APIC to interrupt us every TIMER_MICROSECS microsecs.
	// Set counter to UINT32_MAX, sleep that time, stop counter, and calculate
	// how much it has decreased.
	PIT::configure_sleep(1000);
	write_reg(APIC_TMRINITCNT, UINT32_MAX);
	PIT::perform_sleep();
	write_reg(APIC_LVT_TMR, APIC_DISABLE);
	uint32_t curr_counter = read_reg(APIC_TMRCURRCNT);
	counter_value = UINT32_MAX - curr_counter;

	// Enable interruptions, set counter and re-enable timer, this time in
	// periodic mode.
	enable_interrupts();
	write_reg(APIC_TMRINITCNT, counter_value);
	write_reg(APIC_LVT_TMR, 32 | TMR_PERIODIC);
}

void reset_timer() {
	// Reset counter and signal end of interrupt
	write_reg(APIC_TMRINITCNT, counter_value);
	write_reg(APIC_EOI, 0);
}

}