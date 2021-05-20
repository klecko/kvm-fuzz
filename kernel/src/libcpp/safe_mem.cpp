#include "safe_mem.h"

namespace SafeMem {

extern "C" void* safe_memcpy_ins_may_fault;
extern "C" void* safe_memcpy_ins_faulted;
extern "C" void* safe_strlen_ins_may_fault;
extern "C" void* safe_strlen_ins_faulted;

__attribute__((naked))
bool memcpy(void* dest, const void* src, size_t n) {
	asm volatile(
		"mov rcx, rdx;"              // move n to rcx
		"safe_memcpy_ins_may_fault:"
		"rep movsb;"                 // mov from rsi (src) to rdi (dest)
		"safe_memcpy_ins_faulted:"
		"test rcx, rcx;"             // if rcx is not 0, it's because we faulted
		"sete al;"                   // so just return wheter rcx is 0 or not
		"ret;"
	);
}

__attribute__((naked))
ssize_t strlen(const char* s) {
	asm volatile(
		"xor rax, rax;" // look for null byte
		"xor rcx, rcx;"
		"dec rcx;"      // set rcx to -1
		"safe_strlen_ins_may_fault:"
		"repne scasb;"  // scan string until we find a null byte
		"not rcx;"
		"jmp end;"
		"safe_strlen_ins_faulted:"
		"xor ecx, ecx;" // we faulted: set rcx to -1
		"end:"
		"dec rcx;"
		"mov rax, rcx;"
		"ret;"
	);
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