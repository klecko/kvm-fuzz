#ifndef _X86_IDT_H
#define _X86_IDT_H

namespace IDT {

static const int N_IDT_ENTRIES = 256;

void init();

}

#endif