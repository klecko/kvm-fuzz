#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include "common.h"

TEST_CASE("dup") {
	int fd1 = open(input, O_RDONLY);
	REQUIRE(fd1 > 0);

	int fd2 = dup(fd1);
	REQUIRE(fd2 > 0);
	REQUIRE(fd2 != fd1);

	char* buf = new char[8];
	REQUIRE(read_and_check_first_five_bytes(fd1, buf) == 0);
	REQUIRE(read_and_check_next_seven_bytes(fd2, buf) == 0);

	REQUIRE(lseek(fd1, 0, SEEK_SET) == 0);
	REQUIRE(read_and_check_first_five_bytes(fd2, buf) == 0);

	REQUIRE(close(fd2) == 0);

	REQUIRE(read_and_check_next_seven_bytes(fd1, buf) == 0);

	REQUIRE(close(fd1) == 0);
	delete[] buf;
}


TEST_CASE("dup2") {
	int fd1 = open(input, O_RDONLY);
	REQUIRE(fd1 > 0);
	REQUIRE(lseek(fd1, 5, SEEK_SET) == 5);

	int fd2 = open(input, O_RDONLY);
	REQUIRE(fd2 > 0);
	REQUIRE(lseek(fd2, 4, SEEK_SET) == 4);

	REQUIRE(dup2(fd1, fd2) == fd2);

	// fd2 should have been closed, and fd1 should have been duplicated on fd2
	char* buf = new char[8];
	REQUIRE(read_and_check_next_seven_bytes(fd2, buf) == 0);

	REQUIRE(lseek(fd2, 0, SEEK_SET) == 0);
	REQUIRE(read_and_check_first_five_bytes(fd1, buf) == 0);

	// Dup non open fd should fail
	const int other_fd = 123;
	REQUIRE(dup2(other_fd, fd2) == -1);
	REQUIRE(errno == EBADF);

	// Dup to non open fd
	REQUIRE(dup2(fd2, other_fd) == other_fd);

	REQUIRE(close(fd1) == 0);
	REQUIRE(close(fd2) == 0);
	REQUIRE(close(other_fd) == 0);
	delete[] buf;
}

TEST_CASE("dup2 invalid fd") {
	int fd_limit = get_fd_limit();
	int fd = open(input, O_RDONLY);
	REQUIRE(fd > 0);

	REQUIRE(dup2(fd, fd_limit) == -1);
	REQUIRE(errno == EBADF);

	REQUIRE(close(fd) == 0);
}

TEST_CASE("dup no fd available") {
	int fd_limit = get_fd_limit();
	int fd = open(input, O_RDONLY);
	REQUIRE(fd == 3);

	for (int i = 4; i < fd_limit; i++) {
		REQUIRE(dup2(fd, i) == i);
	}

	REQUIRE(dup(fd) == -1);
	REQUIRE(errno == EMFILE);

	REQUIRE(close(fd) == 0);
	for (int i = 4; i < fd_limit; i++) {
		REQUIRE(close(i) == 0);
	}
}

TEST_CASE("dup cloexec") {
	// Dup doesn't copy cloexec
	int fd = open(input, O_RDONLY | O_CLOEXEC);
	REQUIRE(fd > 0);
	REQUIRE(fcntl(fd, F_GETFD) == 1);

	int fd2 = dup(fd);
	REQUIRE(fd2 > 0);
	REQUIRE(fcntl(fd2, F_GETFD) == 0);

	REQUIRE(close(fd) == 0);
	REQUIRE(close(fd2) == 0);
}