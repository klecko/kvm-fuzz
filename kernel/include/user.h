#ifndef _KERNEL_H
#define _KERNEL_H

#include "linux/uio.h"
#include "map"
#include "string"
#include "common.h"
#include "file.h"
#include "syscalls.h"

#define unordered_map map

// Access to global user state
extern string m_elf_path;
extern uintptr_t m_brk;
extern uintptr_t m_min_brk;
extern struct termios2 m_term;
extern unordered_map<int, File> m_open_files;
extern unordered_map<string, struct iovec> m_file_contents;
extern Regs* m_user_regs;

#endif