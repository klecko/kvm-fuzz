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
	REQUIRE(p_private[0] == 0);
	REQUIRE(p_private[1] == 0);
	p_private[1] = 1;

	pid_t pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		REQUIRE(p_private[1] == 1);
		*p_shared = 1;
		p_private[0] = 1;
		// printf("hello from child! %d %d %d\n", getpid(), gettid(), getpgid(0));
		exit(0);
	}

	// printf("hello from parent! %d %d %d, child pid = %d\n", getpid(), gettid(), getpgid(0), pid);
	REQUIRE(waitpid(-1, nullptr, 0) == pid);
	REQUIRE(*p_shared == 1);
	REQUIRE(p_private[0] == 0);
	REQUIRE(p_private[1] == 1);
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
	global = 1;
}

TEST_CASE("thread") {
	REQUIRE(global == 0);
	std::thread t(foo);
	t.join();
	REQUIRE(global == 1);
}

TEST_CASE("wait info") {
	pid_t pid = fork();
	if (!pid) {
		exit(123);
	}

	int status = 0;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 123);
	REQUIRE(!WIFSIGNALED(status));
	REQUIRE(!WIFSTOPPED(status));
	REQUIRE(!WIFCONTINUED(status));
}

TEST_CASE("child munmaps shared") {
	uint8_t* p_shared = (uint8_t*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
	                                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	REQUIRE(p_shared != MAP_FAILED);
	*p_shared = 16;

	pid_t pid = fork();
	if (!pid) {
		REQUIRE(*p_shared == 16);
		REQUIRE(munmap(p_shared, 0x1000) == 0);
		exit(0);
	}
	REQUIRE(waitpid(pid, NULL, 0) == pid);
	REQUIRE(*p_shared == 16);
}

TEST_CASE("parent munmaps shared") {
	uint8_t* p_shared = (uint8_t*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
	                                   MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	REQUIRE(p_shared != MAP_FAILED);
	uint8_t* p_sync = (uint8_t*)mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE,
	                                 MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	REQUIRE(p_sync != MAP_FAILED);
	*p_shared = 16;

	pid_t pid = fork();
	if (!pid) {
		while (!*p_sync) {
			sched_yield();
		}
		REQUIRE(*p_shared == 17);
		exit(0);
	}
	REQUIRE(*p_shared == 16);
	*p_shared = 17;
	REQUIRE(munmap(p_shared, 0x1000) == 0);
	*p_sync = 1;
	REQUIRE(waitpid(pid, NULL, 0) == pid);
}