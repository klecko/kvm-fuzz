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
		next_alloc = hypercall_mmap(NULL, to_alloc, PDE64_NX | PDE64_RW,
		                            MAP_ANONYMOUS | MAP_PRIVATE);
		remaining = to_alloc;

	} else if (size > remaining) {
		// Request more size
		hypercall_mmap((uint8_t*)next_alloc + remaining, to_alloc, PDE64_NX | PDE64_RW,
		               MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED);
		remaining += to_alloc;
	}
	void* ret = next_alloc;
	remaining -= size;
	next_alloc = (uint8_t*)next_alloc + size;

	// We can't use string here for debugging because that would call kmalloc
#if DEBUG == 1
/* 	const size_t sz = 100;
	char msg[sz] = "Allocation of ";
	itoa(size, msg + strlen(msg), sz - strlen(msg));
	strncat(msg, ": ", sz - strlen(msg));
	itoa((uint64_t)ret, msg + strlen(msg), sz - strlen(msg));
	strncat(msg, "\n", sz - strlen(msg));
	hypercall_print(msg); */
#endif
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