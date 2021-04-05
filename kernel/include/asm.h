#ifndef _ASM_H
#define _ASM_H

#include "common.h"

//x86-64 specific MSRs
#define MSR_EFER             0xc0000080 // extended feature register
#define MSR_STAR             0xc0000081 // legacy mode SYSCALL target
#define MSR_LSTAR            0xc0000082 // long mode SYSCALL target
#define MSR_CSTAR            0xc0000083 // compat mode SYSCALL target
#define MSR_SYSCALL_MASK     0xc0000084 // EFLAGS mask for syscall
#define MSR_FS_BASE          0xc0000100 // 64bit FS base
#define MSR_GS_BASE          0xc0000101 // 64bit GS base
#define MSR_KERNEL_GS_BASE   0xc0000102 // SwapGS GS shadow
#define MSR_TSC_AUX          0xc0000103 // Auxiliary TSC
#define MSR_FIXED_CTR0       0x00000309
#define MSR_FIXED_CTR_CTRL   0x0000038D
#define MSR_PERF_GLOBAL_CTRL 0x0000038F


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

inline uint64_t rdcr3() {
	uint64_t val;
	asm volatile(
		"mov %0, cr3"
		: "=r" (val)
		: :
	);
	return val;
}

inline void flush_tlb() {
	asm volatile(
		"mov rax, cr3;"
		"mov cr3, rax;"
		: : : "memory", "rax"
	);
}

inline void flush_tlb_entry(uintptr_t page) {
	asm volatile(
		"invlpg [%0]"
		:
		: "r" (page)
		: "memory"
	);
}

inline uint64_t instructions_executed() {
#ifdef ENABLE_INSTRUCTION_COUNT
	return rdmsr(MSR_FIXED_CTR0);
#else
	return 0;
#endif
}

inline void jump_to_user(void* entry, void* stack) {
	asm volatile (
		// Set user stack, RIP and RFLAGS
		"mov rsp, %[rsp];"
		"mov rcx, %[entry];"
		"mov r11, 0x2;"

		// Clear every other register
		"xor rax, rax;"
		"xor rbx, rbx;"
		"xor rdx, rdx;"
		"xor rdi, rdi;"
		"xor rsi, rsi;"
		"xor rbp, rbp;"
		"xor r8, r8;"
		"xor r9, r9;"
		"xor r10, r10;"
		"xor r12, r12;"
		"xor r13, r13;"
		"xor r14, r14;"
		"xor r15, r15;"

		// Jump to user
		"sysretq;"
		:
		: [rsp]   "a" (stack),
		  [entry] "b" (entry)
		:
	);
}

#endif