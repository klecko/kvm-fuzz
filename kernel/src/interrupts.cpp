#include "interrupts.h"
#include "common.h"
#include "libcpp/safe_mem.h"
#include "scheduler.h"
#include "x86/asm.h"
#include "x86/apic/apic.h"

extern "C" void handle_interrupt(int interrupt, InterruptFrame* frame) {
	// Default interrupt handler, called by default ISRs
	// Some exceptions push a error code, that's why we don't know where's
	// actually rip
	printf("Interrupt %d at %p or %p\n", interrupt, frame->rip, frame->cs);
	TODO
}

__attribute__((interrupt))
void handle_page_fault(InterruptFrame* frame, uint64_t error_code) {
	bool present = error_code & (1 << 0);
	bool write   = error_code & (1 << 1);
	bool user    = error_code & (1 << 2);
	bool execute = error_code & (1 << 4);
	uint64_t fault_addr = rdcr2();
	if (!user) {
		if (SafeMem::handle_safe_access_fault(frame))
			return;
		printf("woops, kernel PF at %p. addr: %p, present: %d, write: %d, ex: %d\n",
		       frame->rip, fault_addr, present, write, execute);
	}
	// ASSERT(user, "woops, kernel PF at %p. addr: %p, present: %d, write: %d, ex: %d",
	//        frame->rip, fault_addr, present, write, execute);

	FaultInfo fault = {
		.rip        = frame->rip,
		.fault_addr = fault_addr,
		.kernel     = !user,
	};
	if (present)
		if (execute)
			fault.type = FaultInfo::Type::Exec;
		else
			fault.type = (write ? FaultInfo::Type::Write :
			                      FaultInfo::Type::Read);
	else
		if (execute)
			fault.type = FaultInfo::Type::OutOfBoundsExec;
		else
			fault.type = (write ? FaultInfo::Type::OutOfBoundsWrite :
			                      FaultInfo::Type::OutOfBoundsRead);

	// This won't return
	hc_fault(&fault);
}

__attribute__((interrupt))
void handle_breakpoint(InterruptFrame* frame) {
	TODO
}

__attribute__((interrupt))
void handle_general_protection_fault(InterruptFrame* frame, uint64_t error_code) {
	FaultInfo fault = {
		.type = FaultInfo::Type::GeneralProtectionFault,
		.rip = frame->rip,
		.kernel = false, // ?
	};
	hc_fault(&fault);
}

__attribute__((interrupt))
void handle_div_by_zero(InterruptFrame* frame) {
	FaultInfo fault = {
		.type = FaultInfo::Type::DivByZero,
		.rip = frame->rip,
		.fault_addr = 0,
		.kernel = false, // ?
	};
	hc_fault(&fault);
}

__attribute__((interrupt))
void handle_stack_segment_fault(InterruptFrame* frame, uint64_t error_code) {
	FaultInfo fault = {
		.type = FaultInfo::Type::StackSegmentFault,
		.rip = frame->rip,
		.fault_addr = 0,
		.kernel = false, // ?
	};
	hc_fault(&fault);
}

__attribute__((interrupt))
void handle_apic_timer(InterruptFrame* frame) {
	// printf("hello from timer\n");
	ASSERT(!Scheduler::is_running(), "we're not ready for multitasking!!");
	APIC::reset_timer();
}