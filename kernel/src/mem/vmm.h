// Kernel virtual memory manager

#ifndef _MEM_VMM_H
#define _MEM_VMM_H

#include "heap.h"
#include "page_table.h"

namespace VMM {

void init();
PageTable& kernel_page_table();
Heap& kernel_heap();
bool alloc_page(void* addr);
bool alloc_pages(void* addr, size_t n);


}

#endif