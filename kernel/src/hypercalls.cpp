#include <stdarg.h>
#include "hypercalls.h"

// Keep this the same as in the hypervisor!
enum Hypercall : size_t {
	Test,
	Mmap,
	Ready,
	Print,
	GetInfo,
	GetFileLen,
	GetFileName,
	GetFile,
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
void hc_test(size_t arg) {
	hypercall(Hypercall::Test);
}

__attribute__((naked))
void* hc_mmap(void* addr, size_t size, uint64_t page_flags, int flags) {
	hypercall(Hypercall::Mmap);
}

__attribute__((naked))
void hc_ready() {
	hypercall(Hypercall::Ready);
}

__attribute__((naked))
void hc_print(const char* msg) {
	hypercall(Hypercall::Print);
}

const size_t out_buf_size = 1024;
char out_buf[out_buf_size];
size_t used = 0;
void hc_print(char c) {
	// Add the char to the buffer. Print only if it's a line break or if the
	// buffer is full
	out_buf[used++] = c;
	if (c == '\n' || used == out_buf_size-1) {
		out_buf[used] = 0;
		hc_print(out_buf);
		used = 0;
	}
}

void hc_print(const string& msg) {
	hc_print(msg.c_str());
}

__attribute__((naked))
void hc_get_info(VmInfo* info) {
	hypercall(Hypercall::GetInfo);
}

__attribute__((naked))
size_t hc_get_file_len(size_t n) {
	hypercall(Hypercall::GetFileLen);
}

__attribute__((naked))
void hc_get_file_name(size_t n, char* buf) {
	hypercall(Hypercall::GetFileName);
}

__attribute__((naked))
void hc_get_file(size_t n, void* buf) {
	hypercall(Hypercall::GetFile);
}

__attribute__((naked))
void hc_end_run() {
	hypercall(Hypercall::EndRun);
}