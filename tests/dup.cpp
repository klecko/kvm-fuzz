#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include "common.h"
#include "catch.hpp"


TEST_CASE("dup") {
	int fd1 = open(input, O_RDONLY);
	REQUIRE(fd1 > 0);

	int fd2 = dup(fd1);
	REQUIRE(fd2 > 0);
	REQUIRE(fd2 != fd1);

	char* buf = new char[8];
	REQUIRE(read(fd1, buf, 5) == 5);
	buf[5] = 0;
	REQUIRE(strcmp(buf, "hello") == 0);

	REQUIRE(read(fd2, buf, 7) == 7);
	buf[7] = 0;
	REQUIRE(strcmp(buf, " world1") == 0);

	REQUIRE(lseek(fd1, 0, SEEK_SET) == 0);
	REQUIRE(read(fd2, buf, 5) == 5);
	buf[5] = 0;
	REQUIRE(strcmp(buf, "hello") == 0);

	REQUIRE(close(fd2) == 0);

	REQUIRE(read(fd1, buf, 7) == 7);
	buf[7] = 0;
	REQUIRE(strcmp(buf, " world1") == 0);

	REQUIRE(close(fd1) == 0);
}