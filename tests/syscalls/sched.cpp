#include "common.h"

#include <sched.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>

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


TEST_CASE("sched_yield") {
	uint8_t* p_shared = (uint8_t*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
	                                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	pid_t pid = fork();
	if (!pid) {
		// If sched_yield is a no-op, clone returns to the child, and APIC is
		// disabled, then this will loop forever.
		while (!*p_shared) {
			sched_yield();
		}
		exit(0);
	}
	*p_shared = 1;
	REQUIRE(waitpid(-1, nullptr, 0) == pid);

}