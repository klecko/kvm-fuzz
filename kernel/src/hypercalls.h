#ifndef _HYPERCALLS_H
#define _HYPERCALLS_H

#include "linux/limits.h"
#include "linux/termios.h"
#include "string"
#include "common.h"

struct phinfo_t {
    uint64_t e_phoff;      /* Program header table file offset */
    uint16_t e_phentsize;  /* Program header table entry size */
    uint16_t e_phnum;      /* Program header table entry count */
};

// Keep this the same as in the hypervisor
struct VmInfo {
	char elf_path[PATH_MAX];
	uintptr_t brk;
	size_t num_files;
	void (**constructors)(void);
	size_t num_constructors;
	void* user_entry;
	void* elf_entry;
	void* elf_load_addr;
	void* interp_base;
	phinfo_t phinfo;
	struct termios2 term;
};

// Keep this the same as in the hypervisor
struct FaultInfo {
	enum Type {
		Read,
		Write,
		Exec,
		OutOfBoundsRead,
		OutOfBoundsWrite,
		OutOfBoundsExec,
		AssertionFailed,
		DivByZero,
		GeneralProtectionFault,
		StackSegmentFault,
	};

	Type type;
	uint64_t rip;
	uint64_t fault_addr;
	bool kernel;
};

// Keep this the same as in the hypervisor
struct MemInfo {
	void* mem_start;
	size_t mem_length;
	void* physmap_vaddr;
};

enum class RunEndReason {
	Exit,
	Debug,
	Crash,
	Timeout,
	Unknown = -1,
};

void hc_test(size_t arg);
void hc_print(const char* msg);
void hc_print(const char* buf, size_t len);
void hc_print(char c);
void hc_print(const string& msg);
void hc_get_mem_info(MemInfo* info);
void* hc_get_kernel_brk();
void hc_get_info(VmInfo* info);
size_t hc_get_file_len(size_t n);
void hc_get_file_name(size_t n, char* buf);
void hc_submit_file_pointers(size_t n, void* buf, size_t* length_ptr);
void hc_submit_timeout_pointers(size_t* timer_ptr, size_t* timeout_ptr);
void hc_print_stacktrace(uint64_t rsp, uint64_t rip, uint64_t rbp);
void hc_end_run(RunEndReason reason, void* info);

#endif