#include "vmm.h"
#include "pmm.h"

namespace VMM {

static KernelPageTable g_kernel_page_table;
static Heap g_kernel_heap;

void init() {
	g_kernel_page_table.init();
	g_kernel_heap.init(hc_get_kernel_brk());
	dbgprintf("VMM initialized\n");
}

KernelPageTable& kernel_page_table() {
	return g_kernel_page_table;
}

Heap& kernel_heap() {
	return g_kernel_heap;
}

bool alloc_page(void* addr) {
	return alloc_pages(addr, 1);
}
	// Don't call PMM::alloc_frames here, as that uses vector and needs memory

bool alloc_pages(void* addr, size_t n) {
	uintptr_t addr_flat = (uintptr_t)addr;
	ASSERT(IS_PAGE_ALIGNED(addr_flat), "not aligned addr: %p", addr);
	for (size_t i = 0; i < n; i++) {
		uintptr_t page_base = addr_flat + i*PAGE_SIZE;
		uintptr_t frame = PMM::alloc_frame();
		if (!frame)
			return false;
		uint64_t page_flags =
			PageTableEntry::ReadWrite | PageTableEntry::Global |
			PageTableEntry::NoExecute | PageTableEntry::Present;
		if (!g_kernel_page_table.map(page_base, frame, page_flags))
			return false;
	}
	return true;
}

bool alloc_pages(uintptr_t addr, size_t n) {
	ASSERT(IS_PAGE_ALIGNED(addr), "not aligned addr: %p", addr);
	uintptr_t page_base = addr;
	for (size_t i = 0; i < n; i++, page_base += PAGE_SIZE) {
		uintptr_t frame = PMM::alloc_frame();
		if (!frame)
			return false;
		uint64_t page_flags =
			PageTableEntry::ReadWrite | PageTableEntry::Global |
			PageTableEntry::NoExecute | PageTableEntry::Present;
		if (!g_kernel_page_table.map(page_base, frame, page_flags))
			return false;
	}
	return true;
}

}