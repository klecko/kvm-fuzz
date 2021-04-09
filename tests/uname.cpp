#include <sys/utsname.h>
#include <cstring>
#include "common.h"
#include "catch.hpp"

TEST_CASE("uname") {
	struct utsname data;
	REQUIRE(uname(&data) == 0);

	// Don't check exact values of other fields, as we want these tests
	// to also succeed in host system. Correctness of other fields should be
	// checked by libc.
	REQUIRE(strcmp(data.sysname, "Linux") == 0);
	REQUIRE(strcmp(data.machine, "x86_64") == 0);
	REQUIRE(strchr(data.release, 0) != NULL);
}