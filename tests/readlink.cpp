#include <unistd.h>
#include <linux/limits.h>
#include <cstring>
#include "common.h"
#include "catch.hpp"

const char path[] = "/proc/self/exe";

TEST_CASE("readlink") {
	char buf[PATH_MAX];
	REQUIRE(readlink(path, buf, 0) == -1);
	REQUIRE(errno == EINVAL);
	REQUIRE(readlink(path, buf, 4) == 4);
}