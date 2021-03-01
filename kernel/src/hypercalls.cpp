#include <stdarg.h>
#include "hypercalls.h"

// Keep this the same as in the hypervisor!
enum Hypercall : size_t {
	Test,
	Mmap,
	Ready,
	Print,
	GetInfo,
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
void* hypercall_mmap(void* addr, size_t size, uint64_t page_flags, int flags) {
	hypercall(Hypercall::Mmap);
}

__attribute__((naked))
void hypercall_ready() {
	hypercall(Hypercall::Ready);
}

__attribute__((naked))
void hypercall_print(const char* msg) {
	hypercall(Hypercall::Print);
}

const size_t out_buf_size = 1024;
char out_buf[out_buf_size];
size_t used = 0;
void hypercall_print(char c) {
	// Add the char to the buffer. Print only if it's a line break or if the
	// buffer is full
	out_buf[used++] = c;
	if (c == '\n' || used == out_buf_size-1) {
		out_buf[used] = 0;
		hypercall_print(out_buf);
		used = 0;
	}
}

void hypercall_print(const string& msg) {
	hypercall_print(msg.c_str());
}

__attribute__((naked))
void hypercall_get_info(VmInfo* info) {
	hypercall(Hypercall::GetInfo);
}

__attribute__((naked))
void hypercall_end_run() {
	hypercall(Hypercall::EndRun);
}