#include "common.h"

#include <sched.h>
#include <syscall.h>

TEST_CASE("sched_getaffinity libc") {
	cpu_set_t set;
	CPU_ZERO(&set);
	int ret = sched_getaffinity(0, sizeof(set), &set);
	REQUIRE(ret == 0);

	REQUIRE(CPU_ISSET(0, &set));
}

TEST_CASE("sched_getaffinity syscall") {
	unsigned long bitmap[16] = {0};
	long ret = syscall(SYS_sched_getaffinity, 0, sizeof(bitmap), bitmap);
	REQUIRE(ret == 8);
	REQUIRE((bitmap[0] & 1) == 1);
}