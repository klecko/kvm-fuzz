#ifndef _LIBCPP_SAFE_MEM_H
#define _LIBCPP_SAFE_MEM_H

#include "common.h"
#include "interrupts.h"

namespace SafeMem {

bool memcpy(void* dest, const void* src, size_t n);
ssize_t strlen(const char* s);

bool handle_safe_access_fault(InterruptFrame* frame);

}

#endif