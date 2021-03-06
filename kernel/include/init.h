#ifndef _INIT_H
#define _INIT_H

// Kernel startup functions, implemented in their respective files
void init_tss();
void init_gdt();
void init_idt();
void init_syscall();

#endif