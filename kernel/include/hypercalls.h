#ifndef _HYPERCALLS_H
#define _HYPERCALLS_H

#include <string>
#include <linux/limits.h>
#include "common.h"

// PTE bits, needed for argument `page_flags` in `hc_mmap`
#define PDE64_PRESENT  (1 << 0)
#define PDE64_RW       (1 << 1)
#define PDE64_USER     (1 << 2)
#define PDE64_ACCESSED (1 << 5)
#define PDE64_DIRTY    (1 << 6)
#define PDE64_PS       (1 << 7)
#define PDE64_G        (1 << 8)
#define PDE64_NX       0 // (1LU << 63) // TODO

struct VmInfo {
	char elf_path[PATH_MAX];
	void* brk;
	size_t num_files;
	void (**constructors)(void);
	size_t num_constructors;
};

struct FaultInfo {
	enum Type {
		Read,
		Write,
		Exec,
		OutOfBoundsRead,
		OutOfBoundsWrite,
		OutOfBoundsExec,
	};

	Type type;
	uint64_t rip;
	uint64_t fault_addr;
};

void hc_test(size_t arg);
void* hc_mmap(void* addr, size_t size, uint64_t page_flags, int flags);
void hc_ready();
void hc_print(const char* msg);
void hc_print(char c);
void hc_print(const string& msg);
void hc_get_info(VmInfo* info);
size_t hc_get_file_len(size_t n);
void hc_get_file_name(size_t n, char* buf);
void hc_set_file_buf(size_t n, void* buf);
void hc_fault(FaultInfo* fault);
void hc_end_run();

#endif