#include <stddef.h>
#include <stdint.h>
#include "libcpp.h"
#include "hypercalls.h"

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
