#include <limits.h>
#include <cstring>
#include <syscall.h>
#include <unistd.h>
#include "common.h"

// Use syscall here, as library wrapper implements caching and other stuff
// we don't care about
volatile int sys_getcwd(char* buf, size_t size) {
	return syscall(SYS_getcwd, buf, size);
}

bool is_ascii(const char* s) {
	while (*s && isascii(*s))
		s++;
	return *s == 0;
}

TEST_CASE("getcwd") {
	char buf[PATH_MAX];
	REQUIRE(sys_getcwd(buf, 1) == -1);
	REQUIRE(errno == ERANGE);

	REQUIRE(sys_getcwd((char*)1234, 12341234) == -1);
	REQUIRE(errno == EFAULT);

	REQUIRE(sys_getcwd(buf, sizeof(buf)) > 0);
	REQUIRE(is_ascii(buf));
}

TEST_CASE("chdir") {
	// Current functionality implemented
	char buf[PATH_MAX];
	REQUIRE(sys_getcwd(buf, sizeof(buf)) > 0);
	REQUIRE(chdir(buf) == 0);
}