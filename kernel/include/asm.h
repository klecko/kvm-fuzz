#ifndef _ASM_H
#define _ASM_H

#include "common.h"

//x86-64 specific MSRs
#define MSR_EFER           0xc0000080 // extended feature register
#define MSR_STAR           0xc0000081 // legacy mode SYSCALL target
#define MSR_LSTAR          0xc0000082 // long mode SYSCALL target
#define MSR_CSTAR          0xc0000083 // compat mode SYSCALL target
#define MSR_SYSCALL_MASK   0xc0000084 // EFLAGS mask for syscall
#define MSR_FS_BASE        0xc0000100 // 64bit FS base
#define MSR_GS_BASE        0xc0000101 // 64bit GS base
#define MSR_KERNEL_GS_BASE 0xc0000102 // SwapGS GS shadow
#define MSR_TSC_AUX        0xc0000103 // Auxiliary TSC

inline void wrmsr(unsigned int msr, uint64_t val) {
	asm volatile(
		"wrmsr"
		:
		: "c" (msr),
		  "a" (val & 0xFFFFFFFF),
		  "d" (val >> 32)
		: "memory"
	);
}

inline uint64_t rdmsr(unsigned int msr) {
	uint32_t hi, lo;
	asm volatile(
		"rdmsr"
		: "=d" (hi),
		  "=a" (lo)
		: "c" (msr)
		: "memory"
	);
	return ((uint64_t)hi << 32) | lo;
}

inline uint64_t rdcr2() {
	uint64_t val;
	asm volatile(
		"mov %0, cr2"
		: "=r" (val)
		: :
	);
	return val;
}

#endif