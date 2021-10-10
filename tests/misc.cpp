#include "common.h"

TEST_CASE("invalid syscall") {
	int ret = syscall(12345);
	REQUIRE(ret == -1);
	REQUIRE(errno == ENOSYS);
}