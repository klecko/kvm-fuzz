#include <unistd.h>
#include <linux/limits.h>
#include <cstring>
#include <sys/param.h>
#include "common.h"

const char self_exe[] = "/proc/self/exe";

TEST_CASE("readlink") {
	char buf[PATH_MAX] = {0};
	REQUIRE(readlink(self_exe, buf, 0) == -1);
	REQUIRE(errno == EINVAL);

	REQUIRE(readlink(self_exe, buf, 1) == 1);
	REQUIRE(buf[0] == '/');

	ssize_t size = readlink(self_exe, buf, sizeof(buf));
	REQUIRE(size != -1);
	buf[MIN(size, 255)] = 0;
	const char* base_name = strrchr(buf, '/');
	REQUIRE(base_name != NULL);
	base_name += 1;
	REQUIRE(strcmp(base_name, "syscalls_tests") == 0);
}