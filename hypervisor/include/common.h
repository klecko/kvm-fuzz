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

// If disabled, input file will be chose from the initial corpus but it will
// not be mutated
#define ENABLE_MUTATIONS

// Enables KVM dirty log ring, available from Linux 5.11. If disabled, the
// usual bitmap is used
//#define ENABLE_KVM_DIRTY_LOG_RING

// Enables breakpoints-based code coverage. A breakpoint is placed at the start
// of every basic block. When an input hits a breakpoint, it is removed and the
// input is added to the corpus. This provides basic block coverage instead of
// edge coverage, but is MUCH cheaper than Intel PT
//#define ENABLE_COVERAGE_BREAKPOINTS

// Enables Intel PT for code coverage. Currently, KVM-PT is used for tracing
// and libxdc for decoding. There are some performance issues :P
//#define ENABLE_COVERAGE_INTEL_PT
//#define COVERAGE_BITMAP_SIZE 64*1024


#if defined(ENABLE_COVERAGE_BREAKPOINTS) || defined(ENABLE_COVERAGE_INTEL_PT)
	#define ENABLE_COVERAGE
#endif

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

#define printf_once(...) do {                                    \
	static atomic_flag once = ATOMIC_FLAG_INIT;                  \
	if (!once.test_and_set()) {                                  \
		printf("[ONCE] ");                                       \
		printf(__VA_ARGS__);                                     \
	}                                                            \
} while (0)

#define ioctl_chk(fd, req, arg)         \
	({                                  \
		int ret = ioctl(fd, req, arg);  \
		ERROR_ON(ret == -1, #req);      \
		ret;                            \
	})


#endif
