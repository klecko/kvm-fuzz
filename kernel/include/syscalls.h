#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include "common.h"

uint64_t handle_syscall(int nr, uint64_t arg0, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5);

#endif