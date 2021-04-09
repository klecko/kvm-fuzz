#include <unistd.h>
#include <sys/mman.h>
#include "common.h"
#include "catch.hpp"

const int PAGE_SIZE = 0x1000;

TEST_CASE("brk basic") {
	uintptr_t cur_brk, new_brk;
	uintptr_t inc = PAGE_SIZE * 2 - 1;
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

TEST_CASE("brk down vmas") {
	// Get initial brk
	char* initial_brk = (char*)sbrk(0);
	REQUIRE(initial_brk != (char*)-1);

	// Perform two brk, adding one page each time
	char* addr = initial_brk + PAGE_SIZE;
	REQUIRE(brk(addr) == 0);
	addr += PAGE_SIZE;
	REQUIRE(brk(addr) == 0);

	// Change protections
	REQUIRE(mprotect(addr - PAGE_SIZE, PAGE_SIZE,
	                 PROT_READ | PROT_WRITE | PROT_EXEC) == 0);

	// Allocate one more page and try to deallocate everything
	addr += PAGE_SIZE;
	REQUIRE(brk(addr) == 0);
	REQUIRE(brk(initial_brk) == 0);
}

TEST_CASE("brk unaligned and OOM") {
	// Get initial brk
	char* initial_brk = (char*)sbrk(0);
	REQUIRE(initial_brk != (char*)-1);

	// Unaligned brks
	char* addr = initial_brk + PAGE_SIZE/4;
	REQUIRE(brk(addr) == 0);
	addr += PAGE_SIZE/4;
	REQUIRE(brk(addr) == 0);
	addr += PAGE_SIZE/2;
	REQUIRE(brk(addr) == 0);

	// OOM
	REQUIRE(brk((void*)-1) == -1);
	REQUIRE(errno == ENOMEM);
}