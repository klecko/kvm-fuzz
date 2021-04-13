#ifndef _KERNEL_H
#define _KERNEL_H

// #include "linux/uio.h"
// #include "map"
// #include "string"
// #include "common.h"
// #include "file.h"
// #include "syscalls.h"

// #define unordered_map map

// // Access to global user state
// extern struct termios2 m_term;
// extern unordered_map<string, struct iovec> m_file_contents;

#include "common.h"
void start_user(int argc, char** argv, const VmInfo& info);

#endif