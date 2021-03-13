#include "init.h"
#include "common.h"
#include "gdt.h"
#include "asm.h"
#include "syscalls.h"

static void* g_kernel_stack;
static void* g_user_stack;

// This needs to be in the same file as syscall_entry, so it can be called
// from there without dirtying any reg
static uint64_t _handle_syscall(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5,
                                uint64_t rip)
{
	register int nr asm("eax");
	return handle_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5, rip);
}

// Warning: -fpie is needed for these to use relative addressing so it doesn't
// dirty any other register
__attribute__((__always_inline__)) inline
static void save_kernel_stack() {
	asm volatile("mov %[kernel_stack], rsp;" : [kernel_stack] "=m"(g_kernel_stack) : :);
}

__attribute__((__always_inline__)) inline
static void save_user_stack() {
	asm volatile("mov %[user_stack], rsp;" : [user_stack] "=m"(g_user_stack) : :);
}

__attribute__((__always_inline__)) inline
static void restore_kernel_stack() {
	asm volatile("mov rsp, %[kernel_stack];" : [kernel_stack] "=m"(g_kernel_stack) : :);
}

__attribute__((__always_inline__)) inline
static void restore_user_stack() {
	asm volatile("mov rsp, %[user_stack];" : [user_stack] "=m"(g_user_stack) : :);
}

__attribute__((naked))
static void syscall_entry() {
	//asm volatile("hlt");
	save_user_stack();
	restore_kernel_stack();

	asm volatile(
	// Save non-callee-saved registers. This includes rcx (return address)
	// and r11 (rflags)
		"push rdi;"
		"push rsi;"
		"push rdx;"
		"push rcx;"
		"push r8;"
		"push r9;"
		"push r10;"
		"push r11;"

	// Push return address as 7th argument for the handler
		"push rcx;"

	// The forth argument is set in r10. We need to move it to rcx to conform to
	// C ABI. Arguments should be in: rdi, rsi, rdx, rcx, r8, r9.
		"mov rcx, r10;"

	// Handle syscall. Return value will be held in rax
		"call %[handler];"

	// Restore registers
		"pop rcx;"
		"pop r11;"
		"pop r10;"
		"pop r9;"
		"pop r8;"
		"pop rcx;"
		"pop rdx;"
		"pop rsi;"
		"pop rdi;"
	:
	: [handler] "i"(_handle_syscall) // Inmediate, so it doesn't dirty regs
	:
	);

	//save_kernel_stack();
	restore_user_stack();
	//asm volatile("hlt");
	asm volatile("sysretq");
}

void init_syscall() {
	/*
	[SYSCALL]
	CS.selector = STAR 47:32
	SS.selector = STAR 47:32 + 8

	[SYSRET 64 BITS]
	CS.selector = STAR 63:48 + 16
	SS.selector = STAR 63:48 + 8
	*/
	static_assert(SEGMENT_SELECTOR_KDATA == SEGMENT_SELECTOR_KCODE + 8);
	static_assert(SEGMENT_SELECTOR_UCODE == SEGMENT_SELECTOR_UDATA + 8);
	uint64_t star = 0;
	star |= ((uint64_t)SEGMENT_SELECTOR_KCODE << 32);        // for syscall
	star |= ((uint64_t)(SEGMENT_SELECTOR_UDATA - 8) << 48);  // for sysret
	wrmsr(MSR_STAR, star);
	wrmsr(MSR_LSTAR, (uint64_t)syscall_entry);
	wrmsr(MSR_SYSCALL_MASK, 0x3f7fd5);

	save_kernel_stack();

	printf("Syscall handlet set\n");
}
