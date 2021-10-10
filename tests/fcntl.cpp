#include <fcntl.h>
#include "common.h"

TEST_CASE("fcntl not open fd") {
	REQUIRE(fcntl(3, F_GETFD) == -1);
	REQUIRE(errno == EBADF);
}

TEST_CASE("fcntl") {
	int fd = open(input, O_RDWR);
	REQUIRE(fd > 0);

	// F_DUPFD
	int fd2 = fcntl(fd, F_DUPFD, fd);
	REQUIRE(fd2 == fd + 1);
	int fd3 = fcntl(fd, F_DUPFD_CLOEXEC, fd+3);
	REQUIRE(fd3 == fd + 3);
	REQUIRE(lseek(fd, 123, SEEK_SET) == 123);
	REQUIRE(lseek(fd2, 0, SEEK_CUR) == 123);
	REQUIRE(close(fd2) == 0);

	// F_GETFD and F_SETFD: checks and sets O_CLOEXEC
	REQUIRE(fcntl(fd, F_GETFD) == 0);
	REQUIRE(fcntl(fd3, F_GETFD) == FD_CLOEXEC);
	REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	REQUIRE(fcntl(fd3, F_SETFD, 0) == 0);
	REQUIRE(fcntl(fd, F_GETFD) == FD_CLOEXEC);
	REQUIRE(fcntl(fd3, F_GETFD) == 0);
	REQUIRE(close(fd3) == 0);

	// F_GETFL: gets flags
	int flags = fcntl(fd, F_GETFL);
	REQUIRE((flags & O_ACCMODE) == O_RDWR);

	REQUIRE(close(fd) == 0);
}

TEST_CASE("fcntl DUPFD no fd available ") {
	int fd_limit = get_fd_limit();
	int fd = open(input, O_RDWR);
	REQUIRE(fd > 0);

	REQUIRE(fcntl(fd, F_DUPFD, fd_limit) == -1);
	REQUIRE(errno == EINVAL);

	REQUIRE(fcntl(fd, F_DUPFD, fd_limit - 1) == fd_limit - 1);

	REQUIRE(fcntl(fd, F_DUPFD, fd_limit - 1) == -1);
	REQUIRE(errno == EMFILE);
}

TEST_CASE("fcntl DUPFD cloexec") {
	// DUPFD doesn't copy cloexec
	int fd = open(input, O_RDWR | O_CLOEXEC);
	REQUIRE(fd > 0);
	int fd2 = fcntl(fd, F_DUPFD, 0);
	REQUIRE(fd2 > 0);

	REQUIRE(fcntl(fd, F_GETFD) == FD_CLOEXEC);
	REQUIRE(fcntl(fd2, F_GETFD) == 0);

	REQUIRE(close(fd) == 0);
	REQUIRE(close(fd2) == 0);
}