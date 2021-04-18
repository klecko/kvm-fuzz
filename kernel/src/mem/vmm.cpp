#include "vmm.h"
#include "pmm.h"
#include "x86/asm.h"

namespace VMM {

PageTable g_kernel_page_table;
Heap g_kernel_heap;

void init() {
	g_kernel_page_table.set(rdcr3());
	g_kernel_heap.init(hc_get_kernel_brk());
	dbgprintf("VMM initialized\n");
}

PageTable& kernel_page_table() {
	return g_kernel_page_table;
}

Heap& kernel_heap() {
	return g_kernel_heap;
}

bool alloc_page(void* addr) {
	return alloc_pages(addr, 1);
}

bool alloc_pages(void* addr, size_t n) {
	// Don't call PMM::alloc_frames here, as that uses vector and needs memory
	uintptr_t addr_flat = (uintptr_t)addr;
	ASSERT(IS_PAGE_ALIGNED(addr_flat), "not aligned addr: %p", addr);
	for (size_t i = 0; i < n; i++) {
		uintptr_t page_base = addr_flat + i*PAGE_SIZE;
		uintptr_t frame = PMM::alloc_frame();
		if (!frame)
			return false;
		uint64_t page_flags = PageTableEntry::ReadWrite |
			PageTableEntry::NoExecute | PageTableEntry::Global;
		if (!g_kernel_page_table.map(page_base, frame, page_flags))
			return false;
	}
	return true;
}


}