#include "common.h"
#include <thread>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

TEST_CASE("fork") {
	printf("FORK TEST --------------------------------------------------\n");
	uint8_t* p_shared = (uint8_t*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
	                                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	uint8_t* p_private = (uint8_t*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
	                                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	REQUIRE(p_shared != MAP_FAILED);
	REQUIRE(p_private != MAP_FAILED);
	REQUIRE(*p_shared == 0);
	REQUIRE(*p_private == 0);

	pid_t pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		for (volatile int i = 0; i < 12345678; i++);
		*p_shared = 1;
		*p_private = 1;
		// printf("hello from child! %d %d %d\n", getpid(), gettid(), getpgid(0));
		exit(0);
	}

	// printf("hello from parent! %d %d %d, child pid = %d\n", getpid(), gettid(), getpgid(0), pid);
	REQUIRE(waitpid(0, nullptr, 0) != -1);
	REQUIRE(*p_shared == 1);
	REQUIRE(*p_private == 0);
}

TEST_CASE("pids fork") {
	pid_t parent_pid = getpid(), parent_tid = gettid(), parent_pgid = getpgid(0);
	pid_t pid = fork();
	if (pid == 0) {
		pid_t child_pid = getpid(), child_tid = gettid(), child_pgid = getpgid(0),
		      child_ppid = getppid();
		REQUIRE(child_pid != parent_pid);
		REQUIRE(child_tid != parent_tid);
		REQUIRE(child_pgid == parent_pgid);
		REQUIRE(child_ppid == parent_pid);
		exit(0);
	}
	REQUIRE(true);
}


// void foo() {
// 	printf("hello from thread!\n");
// }

// TEST_CASE("thread") {
// 	printf("THREAD TEST --------------------------------------------------\n");
// 	std::thread t(foo);
// 	if (t.joinable())
// 		t.join();
// }
