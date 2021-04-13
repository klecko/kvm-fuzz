#ifndef _INTERRUPTS_H
#define _INTERRUPTS_H
#include "common.h"

enum ExceptionNumber {
	DivByZero = 0,
	Debug,
	NonMaskableInsterrupt,
	Breakpoint,
	Overflow,
	BoundRangeExceeded,
	InvalidOpcode,
	DeviceNotAvailable,
	DoubleFault,
	_reserved1,
	InvalidTSS,
	SegmentNotPresent,
	StackSegmentFault,
	GeneralProtectionFault,
	PageFault,
	_reserved2,
	x87FloatingPointException,
	AlignmentCheck,
	MachineCheck,
	SIMDFloatingPointException,
	VirtualizationException,
	_reserved3,
	SecurityException,
	_reserved4,
	TripleFault
};

enum IRQNumber {
	APICTimer = 32,
};

struct InterruptFrame {
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
};

// Entry point of interrupts
void handle_page_fault(InterruptFrame* frame, uint64_t error_code);
void handle_breakpoint(InterruptFrame* frame);
void handle_general_protection_fault(InterruptFrame* frame, uint64_t error_code);
void handle_div_by_zero(InterruptFrame* frame);
void handle_stack_segment_fault(InterruptFrame* frame, uint64_t error_code);
void handle_apic_timer(InterruptFrame* frame);

#endif