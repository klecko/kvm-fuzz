#include <stddef.h>
#include <stdint.h>
#include "libcpp.h"
#include "hypercalls.h"

#define DEBUG 1

#define ASSERT(expr, ...) do {  \
	if (!(expr)) {              \
		asm("hlt");             \
	}                           \
} while (0)


#define ERROR_ON(expr, ...) do { \
	if (expr) {                  \
		asm("hlt");              \
	}                            \
} while(0)

#define TODO ASSERT(false, "TODO");

#if DEBUG == 1
#define dbgprint(msg) hypercall_print(msg)
#else
#define dbgprint(msg) ((void)0)
#endif