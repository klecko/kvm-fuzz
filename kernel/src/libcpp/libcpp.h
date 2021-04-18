#ifndef _LIBCPP_LIBCPP_H
#define _LIBCPP_LIBCPP_H

#include "asm-generic/errno-base.h"
#include "common.h"
#include "printf.h"
#include "string"
#include "user_ptr.h"

void* kmalloc(size_t size);
void  kfree(void* p);

void* operator new(size_t size);
void* operator new[](size_t size);
void operator delete(void* p);
void operator delete[](void* p);

// I have no idea where this should go
ssize_t print_user(UserPtr<const void*> buf, size_t len);

bool copy_to_user(UserPtr<void*> dest, const void* src, size_t n);
bool copy_from_user(void* dest, UserPtr<const void*> src, size_t n);
bool copy_string_from_user(UserPtr<const char*> src, string& dst);

template <class T>
inline bool copy_from_user(T* dest, UserPtr<const T*> src) {
	return copy_from_user(dest, src, sizeof(T));
}

template <class T>
inline bool copy_to_user(UserPtr<T*> dest, const T* src) {
	return copy_to_user(dest, src, sizeof(T));
}

inline void memcpy(void* dest, const void* src, size_t n) {
	for (size_t i = 0; i < n; i++)
		((uint8_t*)(dest))[i] = ((uint8_t*)src)[i];
}

inline void memset(void* dest, int c, size_t n) {
	for (size_t i = 0; i < n; i++) {
		((uint8_t*)(dest))[i] = c;
	}
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

template<typename T>
string to_str(T);

template<typename T>
char* itoa(T val, char* buf, size_t bufsize);

size_t strlen(const char* s);

char* strncat(char* dest, const char* src, size_t size);

template<typename T>
constexpr T&& move(T& arg) {
    return static_cast<T&&>(arg);
}

template<typename T>
string to_str(T val) {
	string ret;
	bool negative = val < 0;
	if (negative)
		val *= -1;
	do {
		ret = ('0' + val%10) + ret;
		val /= 10;
	} while (val);
	if (negative)
		ret = '-' + ret;
	return ret;
}

template<typename T>
char* itoa(T val, char* buf, size_t bufsize) {
	ASSERT(bufsize > 0, "itoa: zero size buf");
	char* p = buf;
	if(val < 0){
		*p++ = '-';
		val *= -1;
	}

	// Move pointer to the end
	T shifter = val;
	do{
		++p;
		shifter = shifter/10;
	}while(shifter);

	// Check if there's enough space
	ASSERT((uintptr_t)p - (uintptr_t)buf + 1 <= bufsize, "itoa: buf too small");

	*p = '\0';
	do {
		*--p = '0' + val%10;
		val = val/10;
	} while(val);
	return buf;
}

#endif