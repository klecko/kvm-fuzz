#include <stdarg.h>
#include <string>
#include "hypercalls.h"

// Keep this the same as in the hypervisor!
enum Hypercall : size_t {
	Test,
	Alloc,
	Ready,
	Print,
	GetElfPath,
	EndRun,
};

// This is traduced to:
//    mov eax, `n`;
//    out 16, al;
//    ret;
// That's the body of each hypercall. Arguments are passed via rdi, rsi, etc,
// and return value is put in rax by the hypervisor.

#define hypercall(n)    \
	asm volatile(       \
		"out 16, al;"   \
		"ret;"          \
		:               \
		: "a" (n)       \
		:               \
	)

__attribute__((naked))
void hypercall_test(size_t arg) {
	hypercall(Hypercall::Test);
}

__attribute__((naked))
void* hypercall_alloc(size_t size) {
	hypercall(Hypercall::Alloc);
}

__attribute__((naked))
void hypercall_ready() {
	hypercall(Hypercall::Ready);
}

/* __attribute__((naked))
void _hypercall_print(const char* msg) {
	hypercall(Hypercall::Print);
}

void hypercall_print(const string& msg) {
	// TODO: STL
	_hypercall_print(msg.c_str());
} */

__attribute__((naked))
void hypercall_print(const char* msg) {
	hypercall(Hypercall::Print);
}

__attribute__((naked))
void hypercall_get_elf_path(const char* buf, size_t size) {
	hypercall(Hypercall::GetElfPath);
}

__attribute__((naked))
void hypercall_end_run() {
	hypercall(Hypercall::EndRun);
}