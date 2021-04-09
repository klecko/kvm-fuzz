#include "common.h"
#include "catch.hpp"

TEST_CASE("thread_local") {
	// This looks trivial, but it makes sure arch_prctl ARCH_SET_FS is working,
	// as that's how thread local variables are implemented in x86_64
	// (though if it didn't work, I guess it would crash before getting here,
	// since libc uses it first)
	volatile thread_local int n = 0;
	n = 5;
	REQUIRE(n == 5);
}