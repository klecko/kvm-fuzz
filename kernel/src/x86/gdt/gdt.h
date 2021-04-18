#ifndef _X86_GDT_H
#define _X86_GDT_H

namespace GDT {

// According to syscall and sysret instructions, kernel data must be after
// kernel code, but user data must be before user code.
// Detailed in Kernel::register_syscall
const int N_GDT_ENTRIES          = 7;    // TSS counts twice
const int SEGMENT_SELECTOR_NULL  = 0x00;
const int SEGMENT_SELECTOR_KCODE = 0x08;
const int SEGMENT_SELECTOR_KDATA = 0x10;
const int SEGMENT_SELECTOR_UDATA = 0x18;
const int SEGMENT_SELECTOR_UCODE = 0x20;
const int SEGMENT_SELECTOR_TSS   = 0x28;

void init();

}

#endif