#include <stddef.h>
#include <stdint.h>
#include "libcpp/libcpp.h"
#include "hypercalls.h"

// #define ENABLE_GUEST_OUTPUT
#define ENABLE_INSTRUCTION_COUNT

typedef long ssize_t;

#define hlt() asm("hlt")

#if DEBUG == 1
#define dbgprint(msg) hypercall_print(msg)
#define dbgprintf(...) printf(__VA_ARGS__)
#else
#define dbgprint(msg) ((void)0)
#define dbgprintf(...) ((void)0)
#endif

#define err_header(type) \
	printf(type " at `%s` %s:%d\n", __PRETTY_FUNCTION__, __FILE__, __LINE__);


#define ASSERT(expr, ...) do {                                   \
	if (!(expr)) {                                               \
		err_header("Assertion failed");                          \
		printf("%s: ", __func__);                                \
		printf(__VA_ARGS__);                                     \
		die("\nExpected: `%s`\n", #expr);                        \
	}                                                            \
} while (0)

#define TODO ASSERT(false, "TODO");

#define UNREACHABLE ASSERT(false, "UNREACHABLE")

#define die(...) do {                                            \
	printf(__VA_ARGS__);                                         \
	asm("out 17, al");                                           \
} while(0)

#define printf_once(...) do {                                    \
	static bool once = false;                                    \
	if (!once) {                                                 \
		printf("[ONCE] ");                                       \
		printf(__VA_ARGS__);                                     \
		once = true;                                             \
	}                                                            \
} while (0)
