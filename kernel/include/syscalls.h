#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include "common.h"

// Guest regs that syscall handler can read and modify
struct Regs {
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t rip;
};

uint64_t handle_syscall(int nr, uint64_t arg0, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5, Regs* regs);

#endif