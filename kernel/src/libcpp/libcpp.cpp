#define _GNU_SOURCE
#include "libcpp.h"
#include "hypercalls.h"
#include "mem/vmm.h"
#include "mem/address_space.h"
#include "safe_mem.h"

void* operator new(size_t size) {
	return kmalloc(size);
}

void* operator new[](size_t size) {
	return kmalloc(size);
}

void operator delete(void* p) {
	return kfree(p);
}

void operator delete[](void* p) {
	return kfree(p);
}

void* kmalloc(size_t size) {
	return VMM::kernel_heap().alloc(size);
}

void kfree(void* p) {
	VMM::kernel_heap().free(p);
}

void __cxa_pure_virtual() {
	asm("hlt");
}

// I have no idea where this should go
ssize_t print_user(UserPtr<const void*> buf, size_t len) {
	char* kernel_buf = new char[len];
	if (!kernel_buf)
		return -ENOMEM;
	ssize_t ret = len;
	if (!copy_from_user(kernel_buf, buf, len))
		ret = -EFAULT;
	else
		hc_print(kernel_buf, len);
	delete[] kernel_buf;
	return ret;
}

bool copy_to_user(UserPtr<void*> dest, const void* src, size_t n) {
	if (!AddressSpace::is_user_range(dest.flat(), n))
		return false;
	ASSERT(!AddressSpace::is_user_range((uintptr_t)src, n), "copying from user");
	return SafeMem::memcpy(dest.ptr(), src, n);
}

bool copy_from_user(void* dest, UserPtr<const void*> src, size_t n) {
	if (!AddressSpace::is_user_range(src.flat(), n))
		return false;
	ASSERT(!AddressSpace::is_user_range((uintptr_t)dest, n), "copying to user");
	return SafeMem::memcpy(dest, src.ptr(), n);
}

bool copy_string_from_user(UserPtr<const char*> src, string& dst) {
	ssize_t length = SafeMem::strlen(src.ptr());
	if (length == -1)
		return false;

	// TODO: is there a way to avoid OOM, as we do in print_user?
	dst = string(length, 0);
	return copy_from_user(&dst[0], src, length);
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