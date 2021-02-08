#ifndef _COMMON_H
#define _COMMON_H

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <assert.h>
#include <err.h>
#include <sys/ioctl.h>

#define DEBUG 1

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

#define die(...) err(-1, __VA_ARGS__)

#define ioctl_chk(fd, req, arg)         \
	({                                  \
		int ret = ioctl(fd, req, arg);  \
		if (ret == 1)                   \
			die(#req);                  \
		ret;                            \
	})


#endif
