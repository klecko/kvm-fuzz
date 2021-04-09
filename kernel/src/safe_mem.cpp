#include "safe_mem.h"

namespace SafeMem {

extern "C" void* safe_memcpy_ins_may_fault;
extern "C" void* safe_memcpy_ins_faulted;
extern "C" void* safe_strlen_ins_may_fault;
extern "C" void* safe_strlen_ins_faulted;

bool memcpy(void* dest, const void* src, size_t n) {
	asm volatile(
		"safe_memcpy_ins_may_fault:"
		"rep movsb;"
		"safe_memcpy_ins_faulted:"
		: "=c" (n)    // move rcx to `n` as result
		: "D" (dest), // rdi
		  "S" (src),  // rsi
		  "c" (n)     // rcx
		: "memory"
	);
	if (n > 0) {
		// The 'rep movsb' faulted and the operation wasn't completed
		return false;
	}
	return true;
}

ssize_t strlen(const char* s) {
	ssize_t n;
	asm volatile(
		"safe_strlen_ins_may_fault:"
		"repne scasb;"
		"not rcx;"
		"dec rcx;"
		"jmp end;"
		"safe_strlen_ins_faulted:"
		"xor ecx, ecx;" // set rcx to -1
		"dec rcx;"
		"end:"
		: "=c" (n)    // move rcx to `n` as result
		: "a" (0),    // rax, value we're looking for in the string
		  "c" (-1LL), // rcx, max length
		  "D" (s)     // rdi, string address
	);
	return n;
}

bool handle_safe_access_fault(InterruptFrame* frame) {
	if (frame->rip == (uintptr_t)&safe_memcpy_ins_may_fault)
		frame->rip = (uintptr_t)&safe_memcpy_ins_faulted;
	else if (frame->rip == (uintptr_t)&safe_strlen_ins_may_fault)
		frame->rip = (uintptr_t)&safe_strlen_ins_faulted;
	else
		return false;
	return true;
}

} // namespace SafeMem