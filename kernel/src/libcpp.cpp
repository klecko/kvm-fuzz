#define _GNU_SOURCE
#include "libcpp.h"
#include "hypercalls.h"
#include "mem.h"
#include <sys/mman.h>

void* kmalloc(size_t size) {
	static const size_t INITIAL_ALLOCATION_SIZE = 0x2000;
	static uint8_t* next_alloc = NULL;
	static size_t remaining = 0;

	// Initial allocation
	if (next_alloc == NULL) {
		next_alloc = (uint8_t*)hc_get_kernel_brk();
		dbgprintf("Kernel brk: %p\n", next_alloc);
		Mem::Virt::alloc(next_alloc, INITIAL_ALLOCATION_SIZE, PDE64_NX | PDE64_RW);
		remaining = INITIAL_ALLOCATION_SIZE;
	}

	// Request more size if needed
	if (size > remaining) {
		size_t to_alloc = (size*2 + 0xFFF) & ~0xFFF;
		Mem::Virt::alloc(next_alloc + remaining, to_alloc, PDE64_NX | PDE64_RW);
		remaining += to_alloc;
	}

	void* ret = next_alloc;
	remaining -= size;
	next_alloc += size;

	//dbgprintf("Allocation of %lu: %p\n", size, ret);
	return ret;
}

void kfree(void* p) {
	return;
}

void __cxa_pure_virtual() {
	asm("hlt");
}



size_t strlen(const char* s) {
	size_t len = 0;
	while (*s++) len++;
	return len;
}

char* strncat(char* dest, const char* src, size_t size) {
	char* p = dest + strlen(dest);
	while ((*p++ = *src++) && size--);
	return dest;
}