#ifndef _KERNEL_H
#define _KERNEL_H

#include <map>
#include <string>
#include <sys/uio.h>
#include "common.h"
#include "file.h"

#define unordered_map map

// Access to global kernel state
extern string m_elf_path;
extern void* m_brk;
extern void* m_min_brk;
extern unordered_map<int, File> m_open_files;
extern unordered_map<string, struct iovec> m_file_contents;

#endif