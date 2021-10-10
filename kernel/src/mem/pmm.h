#ifndef _MEM_PMM_H
#define _MEM_PMM_H

#include "common.h"
#include "vector"

namespace PMM {

void init();
size_t memory_length();
uintptr_t alloc_frame();
bool alloc_frames(size_t n, vector<uintptr_t>& frames);
void free_frame(uintptr_t frame);
void* phys_to_virt(uintptr_t phys);
uintptr_t virt_to_phys(void* virt);
uintptr_t dup_frame(uintptr_t frame);
size_t amount_free_frames();
size_t frames_allocated();

}

#endif