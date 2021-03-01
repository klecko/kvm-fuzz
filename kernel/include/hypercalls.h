#ifndef _HYPERCALLS_H
#define _HYPERCALLS_H

#include <string>
#include <linux/limits.h>
#include "common.h"
#include "aux.h"

struct VmInfo {
	char elf_path[PATH_MAX];
	void* brk;
	size_t num_files;
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
void hc_get_file(size_t n, void* buf);
void hc_end_run();

#endif