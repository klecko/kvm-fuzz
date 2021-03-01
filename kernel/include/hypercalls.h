#ifndef _HYPERCALLS_H
#define _HYPERCALLS_H

#include <string>
#include <linux/limits.h>
#include "common.h"

/* 64-bit page entry bits for mmap */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)
#define PDE64_NX 0 // (1LU << 63) // TODO

struct VmInfo {
	char elf_path[PATH_MAX];
	void* brk;
};

void hypercall_test(size_t arg);
void* hypercall_mmap(void* addr, size_t size, uint64_t page_flags, int flags);
void hypercall_ready();
void hypercall_print(const char* msg);
void hypercall_print(const string& msg);
void hypercall_get_info(VmInfo* info);
void hypercall_end_run();

#endif