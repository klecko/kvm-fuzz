#include "apic.h"
#include "x86/asm.h"
#include "x86/pit/pit.h"
#include "mem/vmm.h"
#include "interrupts.h"

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
static uint8_t* g_apic;
static uint32_t g_counter_value;

enum Register : uint16_t {
	ApicId = 0x20,
	TaskPriority = 0x80, // TPR
	EndOfInterrupt = 0xB0, // EOI
	LogicalDestination = 0xD0, // LDR
	DestinationFormat = 0xE0, // DFR
	SpuriousInterruptVector = 0xF0,
	LvtTimer = 0x320,
	LvtPerformanceMonitoring = 0x340,
	LvtLINT0 = 0x350,
	LvtLINT1 = 0x360,
	TimerInitialCount = 0x380,
	TimerCurrentCount = 0x390,
	TimerDivideConfiguration = 0x3e0,
};

enum Enable {
	XApic = 1 << 11,
	X2Apic = 1 << 10,
};

enum Mode {
	OneShot = 0,
	Periodic = 0x20000,
};

enum Divide {
	Div1 = 0xB,
	Div2 = 0x0,
	Div4 = 0x1,
	Div8 = 0x2,
	Div16 = 0x3,
	Div32 = 0x8,
	Div64 = 0x9,
	Div128 = 0xA
};

static void write_reg(Register reg, uint32_t value) {
	*(volatile uint32_t*)(g_apic + (uint16_t)reg) = value;
}

static uint32_t read_reg(Register reg) {
	return *(volatile uint32_t*)(g_apic + (uint16_t)reg);
}

void init() {
	// https://wiki.osdev.org/APIC_timer
	// Get APIC phys address
	uintptr_t phys = rdmsr(MSR_APIC_BASE) & PTL1_MASK;

	// Map it
	g_apic = (uint8_t*)0x1234000; // FIXME: which address should i map it to?
	uint64_t page_flags = PageTableEntry::Present | PageTableEntry::ReadWrite;
	ASSERT(VMM::kernel_page_table().map((uintptr_t)g_apic, phys, page_flags),
	       "failed to map APIC?");

	// Initialize APIC
	write_reg(Register::DestinationFormat, 0x0FFFFFFFF);
	write_reg(Register::LogicalDestination,
	          (read_reg(Register::LogicalDestination) & 0x00FFFFFF) | 1);
	write_reg(Register::LvtTimer, APIC_DISABLE);
	write_reg(Register::LvtPerformanceMonitoring, APIC_NMI);
	write_reg(Register::LvtLINT0, APIC_DISABLE);
	write_reg(Register::LvtLINT1, APIC_DISABLE);
	write_reg(Register::TaskPriority, 0);

	// Enable APIC
	wrmsr(MSR_APIC_BASE, rdmsr(MSR_APIC_BASE) | Enable::XApic);
	write_reg(Register::SpuriousInterruptVector, 0xFF | APIC_SW_ENABLE);

	// Enable timer in one-shot mode
	write_reg(Register::LvtTimer, IRQNumber::APICTimer | Mode::OneShot);
	write_reg(Register::TimerDivideConfiguration, Divide::Div16);

	// Calculate the counter value we'll set.
	// We want APIC to interrupt us every TIMER_MICROSECS microsecs.
	// Set counter to UINT32_MAX, sleep that time, stop counter, and calculate
	// how much it has decreased.
	PIT::configure_sleep(1000);
	write_reg(Register::TimerInitialCount, UINT32_MAX);
	PIT::perform_sleep();
	write_reg(Register::LvtTimer, APIC_DISABLE);
	uint32_t curr_counter = read_reg(Register::TimerCurrentCount);
	g_counter_value = UINT32_MAX - curr_counter;

	// Enable interruptions, set counter and re-enable timer, this time in
	// periodic mode.
	enable_interrupts();
	write_reg(Register::TimerInitialCount, g_counter_value);
	write_reg(Register::LvtTimer, IRQNumber::APICTimer | Mode::Periodic);

	dbgprintf("APIC initialized\n");
}

void reset_timer() {
	// Reset counter and signal end of interrupt
	write_reg(Register::TimerInitialCount, g_counter_value);
	write_reg(Register::EndOfInterrupt, 0);
}

size_t timer_microsecs() {
	return TIMER_MICROSECS;
}

}