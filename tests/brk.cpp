#include <unistd.h>
#include <sys/mman.h>
#include "common.h"
#include "catch.hpp"

TEST_CASE("brk basic", "[brk]") {
	uintptr_t cur_brk, new_brk;
	uintptr_t inc = getpagesize() * 2 - 1;
	unsigned int i;

	cur_brk = (uintptr_t)sbrk(0);
	REQUIRE(cur_brk != (uintptr_t)-1);

	for (i = 0; i < 33; i++) {
		switch (i % 3) {
			case 0:
				new_brk = cur_brk + inc;
				break;
			case 1:
				new_brk = cur_brk;
				break;
			case 2:
				new_brk = cur_brk - inc;
				break;
		}

		REQUIRE(brk((void*)new_brk) == 0);

		cur_brk = (uintptr_t)sbrk(0);
		REQUIRE(cur_brk == new_brk);

		/* Try to write to the newly allocated heap */
		if (i % 3 == 0)
			*((char *)cur_brk) = 0;
	}
}

TEST_CASE("brk down vmas", "[brk]") {
	// Get initial brk
	char* initial_brk = (char*)sbrk(0);
	REQUIRE(initial_brk != (char*)-1);

	// Perform two brk, adding one page each time
	unsigned long page_size = getpagesize();
	char* addr = initial_brk + page_size;
	REQUIRE(brk(addr) == 0);
	addr += page_size;
	REQUIRE(brk(addr) == 0);

	// Change protections
	REQUIRE(mprotect(addr - page_size, page_size,
	                 PROT_READ | PROT_WRITE | PROT_EXEC) == 0);

	// Allocate one more page and try to deallocate everything
	addr += page_size;
	REQUIRE(brk(addr) == 0);
	REQUIRE(brk(initial_brk) == 0);
}