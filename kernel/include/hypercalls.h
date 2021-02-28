#ifndef _HYPERCALLS_H
#define _HYPERCALLS_H

#include <string>
#include "common.h"

void hypercall_test(size_t arg);
void* hypercall_alloc(size_t size);
void hypercall_ready();
void hypercall_print(const string& msg);
void hypercall_get_elf_path(const char* buf, size_t size);
void hypercall_end_run();

#endif