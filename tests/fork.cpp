#include "common.h"
#include <thread>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <sys/syscall.h>

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


// uint8_t global = 0;

// void foo() {
// 	printf("hello from thread!\n");
// 	global = 1;
// }

// TEST_CASE("thread") {
// 	// thread: CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
//     //         CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
//     //         CLONE_CHILD_CLEARTID

//     // thread: 0x3d0f00 0x7ffff87fddf0 0x7ffff87fe9d0 0x7ffff87fe9d0 0x7ffff87fe700
// 	void* stack = mmap(nullptr, 0x10000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
// 	int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
//             CLONE_SYSVSEM | /*CLONE_SETTLS | */CLONE_PARENT_SETTID |
//             CLONE_CHILD_CLEARTID;
// 	REQUIRE(stack != MAP_FAILED);
// 	// clone(foo, stack, flags,)
// 	int parent_tid = 0, child_tid = 0;
// 	int ret = syscall(SYS_clone, flags, stack, &parent_tid, &child_tid, 0);
// 	printf("%d\n", ret);
// }

// TEST_CASE("thread") {
// 	printf("THREAD TEST --------------------------------------------------\n");
// 	REQUIRE(global == 0);
// 	std::thread t(foo);
// 	t.join();
// 	REQUIRE(global == 1);
// }
