#ifndef _MEM_PMM_H
#define _MEM_PMM_H

#include "common.h"
#include "vector"

namespace PMM {

void init();
uintptr_t alloc_frame();
bool alloc_frames(size_t n, vector<uintptr_t>& frames);
void free_frame(uintptr_t frame);
void* phys_to_virt(uintptr_t phys);
size_t amount_free_frames();

}

#endif