#include "common.h"
#include <thread>
#include <unistd.h>

/*
TEST_CASE("fork") {
	printf("FORK TEST --------------------------------------------------\n");
	pid_t pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		printf("hello from child!\n");
		exit(0);
	}
	printf("hello from parent! child pid = %d\n", pid);
	exit(0);
}
*/

// void foo() {
// 	printf("hello from thread!\n");
// }

// TEST_CASE("thread") {
// 	printf("THREAD TEST --------------------------------------------------\n");
// 	std::thread t(foo);
// 	if (t.joinable())
// 		t.join();
// }
