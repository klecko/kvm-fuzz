#include "idt.h"
#include "idt_entry.h"
#include "interrupts.h"
#include "x86/gdt/gdt.h"

// These are defined in default_isrs.asm, and they just call handle_interrupt.
extern uint64_t _defaultISRs;

namespace IDT {

static InterruptDescriptor g_idt[N_IDT_ENTRIES];

void init() {
	static_assert(sizeof(InterruptDescriptor) == 16);

	// Register default Interrupt Service Routines
	uint64_t* defaultISRs = &_defaultISRs;
	for (size_t i = 0; i < 256; i++) {
		g_idt[i].set_present();
		g_idt[i].set_selector(GDT::SEGMENT_SELECTOR_KCODE);
		g_idt[i].set_offset(defaultISRs[i]);
		g_idt[i].set_dpl(3);
		if (i < 32)
			g_idt[i].set_type(InterruptDescriptor::Type::Trap);
		else
			g_idt[i].set_type(InterruptDescriptor::Type::Interrupt);
	}

	// Set DoubleFault to use the first stack of the Interrupt Stack Table
	// located in the TSS. This stack is allocated in gdt.cpp
	g_idt[ExceptionNumber::DoubleFault].set_ist(1);

	// If we don't set -mno-red-zone, we must stack switch every interrupt
	// g_idt[IRQNumber::APICTimer].set_ist(1);

	// Custom ISRS
	g_idt[ExceptionNumber::DivByZero].set_offset((uint64_t)handle_div_by_zero);
	g_idt[ExceptionNumber::Breakpoint].set_offset((uint64_t)handle_breakpoint);
	g_idt[ExceptionNumber::StackSegmentFault]
		.set_offset((uint64_t)handle_stack_segment_fault);
	g_idt[ExceptionNumber::GeneralProtectionFault]
		.set_offset((uint64_t)handle_general_protection_fault);
	g_idt[ExceptionNumber::PageFault].set_offset((uint64_t)handle_page_fault);
	g_idt[IRQNumber::APICTimer].set_offset((uint64_t)handle_apic_timer);

	// Load the IDT
	IDTR idtr = {
		.size   = sizeof(g_idt) - 1,
		.offset = (uint64_t)g_idt
	};
	idtr.load();

	dbgprintf("IDT initialized\n");
}

}