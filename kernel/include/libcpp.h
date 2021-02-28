#ifndef _LIBCPP_H
#define _LIBCPP_H

#include <stddef.h>
#include <stdint.h>

void* kmalloc(size_t size);
void  kfree(void* p);

inline void* operator new(size_t size) {
	return kmalloc(size);
}

inline void* operator new[](size_t size) {
	return kmalloc(size);
}

inline void operator delete(void* p) {
	return kfree(p);
}

inline void operator delete[](void* p) {
	return kfree(p);
}

inline void memcpy(void* dest, const void* src, size_t n) {
	for (size_t i = 0; i < n; i++)
		((uint8_t*)(dest))[i] = ((uint8_t*)src)[i];
}

template <class T>
inline T min(T v1, T v2) {
	return (v1 < v2 ? v1 : v2);
}

template <class T>
inline T max(T v1, T v2) {
	return (v1 > v2 ? v1 : v2);
}

extern "C" void __cxa_pure_virtual();
#endif