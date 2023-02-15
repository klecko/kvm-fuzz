#include "common.h"
#include <thread>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <sys/syscall.h>

TEST_CASE("fork") {
	// printf("FORK TEST --------------------------------------------------\n");
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
		*p_shared = 1;
		*p_private = 1;
		// printf("hello from child! %d %d %d\n", getpid(), gettid(), getpgid(0));
		exit(0);
	}

	// printf("hello from parent! %d %d %d, child pid = %d\n", getpid(), gettid(), getpgid(0), pid);
	REQUIRE(waitpid(-1, nullptr, 0) == pid);
	REQUIRE(*p_shared == 1);
	REQUIRE(*p_private == 0);
	// printf("END FORK TEST --------------------------------------------------\n");
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
	REQUIRE(waitpid(-1, nullptr, 0) == pid);
}

TEST_CASE("double wait") {
	pid_t pid = fork();
	if (pid == 0) {
		exit(0);
	}
	REQUIRE(waitpid(-1, nullptr, 0) == pid);
	REQUIRE(waitpid(-1, nullptr, 0) == -1);
	REQUIRE(errno == ECHILD);
}

uint8_t global = 0;

void foo() {
	printf("hello from thread!\n");
	global = 1;
}

// TEST_CASE("thread") {
// 	printf("THREAD TEST --------------------------------------------------\n");
// 	REQUIRE(global == 0);
// 	std::thread t(foo);
// 	t.join();
// 	REQUIRE(global == 1);
// }
