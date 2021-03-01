#define _GNU_SOURCE
#include "libcpp.h"
#include "hypercalls.h"
#include <sys/mman.h>

void* next_alloc = NULL;
size_t remaining = 0;
void* kmalloc(size_t size) {
	size_t to_alloc = (size*2 + 0xFFF) & ~0xFFF;
	if (next_alloc == NULL) {
		// Initial allocation
		next_alloc = hc_mmap(NULL, to_alloc, PDE64_NX | PDE64_RW,
		                            MAP_ANONYMOUS | MAP_PRIVATE);
		remaining = to_alloc;

	} else if (size > remaining) {
		// Request more size
		hc_mmap((uint8_t*)next_alloc + remaining, to_alloc, PDE64_NX | PDE64_RW,
		        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED);
		remaining += to_alloc;
	}
	void* ret = next_alloc;
	remaining -= size;
	next_alloc = (uint8_t*)next_alloc + size;

	dbgprintf("Allocation of %lu: 0x%lx\n", size, ret);
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