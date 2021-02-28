#include "libcpp.h"
#include "hypercalls.h"

void* next_alloc = NULL;
size_t remaining = 0;
void* kmalloc(size_t size) {
	if (size > remaining) {
		size_t to_alloc = (size*2 + 0xFFF) & ~0xFFF;
		next_alloc = hypercall_alloc(to_alloc);
		remaining = to_alloc;
	}
	void* ret = next_alloc;
	remaining -= size;
	next_alloc += size;
	return ret;
}

void kfree(void* p) {
	return;
}

void __cxa_pure_virtual() {
	asm("hlt");
}