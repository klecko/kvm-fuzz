#ifndef _COMMON_H
#define _COMMON_H

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <assert.h>
#include <err.h>
#include <sys/ioctl.h>
#include <execinfo.h>
#include <unistd.h>
#include <string.h>

//#define ENABLE_KVM_DIRTY_LOG_RING
#define ENABLE_COVERAGE

//#define DEBUG 1

// Type used for guest virtual addresses
typedef uint64_t vaddr_t;

// Type used for indexing guest virtual address
typedef vaddr_t vsize_t;

// Type used for guest physical addresses
typedef uint64_t paddr_t;

// Type used for indexing guest physical addresses
typedef paddr_t psize_t;

#if DEBUG == 1
#define dbgprintf(...) printf(__VA_ARGS__)
#else
#define dbgprintf(...) ((void)0)
#endif

#define err_header(type)                                         \
	fprintf(stderr, type " at `%s` %s:%d\n", __PRETTY_FUNCTION__,\
	        __FILE__, __LINE__);

#define print_backtrace() ((void)0)
/* #define print_backtrace() do {                                   \
	void* array[10];                                             \
	size_t size = backtrace(array, 10);                          \
	fprintf(stderr, "Bracktrace:\n");                            \
	backtrace_symbols_fd(array, size, STDERR_FILENO);            \
	fprintf(stderr, "\n");                                       \
} while (0) */


#define ASSERT(expr, ...) do {                                   \
	if (!(expr)) {                                               \
		print_backtrace();                                       \
		err_header("Assertion failed");                          \
		fprintf(stderr, "%s: ", __func__);                       \
		fprintf(stderr, __VA_ARGS__);                            \
		die("\nExpected: `%s`\n", #expr);                        \
	}                                                            \
} while (0)

#define ERROR_ON(expr, ...) do {                                 \
	if (expr) {                                                  \
		print_backtrace();                                       \
		err_header("Error");                                     \
		fprintf(stderr, __VA_ARGS__);                            \
		die(": %s (-%d)\n", strerror(errno), errno);             \
	}                                                            \
} while (0)

#define TODO ASSERT(false, "TODO");

#define die(...) do {                   \
	fprintf(stderr, __VA_ARGS__);       \
	fflush(stderr);                     \
	fflush(stdout);                     \
	abort();                            \
} while(0)

#define ioctl_chk(fd, req, arg)         \
	({                                  \
		int ret = ioctl(fd, req, arg);  \
		ERROR_ON(ret == -1, #req);      \
		ret;                            \
	})


#endif
