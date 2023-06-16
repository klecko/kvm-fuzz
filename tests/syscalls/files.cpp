#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include "common.h"

TEST_CASE("lseek") {
	int fd = open(input, O_RDONLY);
	REQUIRE(fd > 0);

	struct stat st;
	REQUIRE(fstat(fd, &st) == 0);
	REQUIRE(st.st_size > 0);

	REQUIRE(lseek(fd, 1234, SEEK_SET) == 1234);
	REQUIRE(lseek(fd, -1, SEEK_CUR) == 1233);
	REQUIRE(lseek(fd, -1, SEEK_END) == st.st_size - 1);
	REQUIRE(lseek(fd, -st.st_size, SEEK_CUR) == -1);
	REQUIRE(errno == EINVAL);
	REQUIRE(lseek(fd, -123, SEEK_SET) == -1);
	REQUIRE(errno == EINVAL);

	REQUIRE(close(fd) == 0);
}

TEST_CASE("files") {
	// Check file exists and we have read access
	REQUIRE(access(input, R_OK) == 0);
	REQUIRE(access(input, F_OK) == 0);

	// Open file
	int fd = open(input, O_RDONLY);
	REQUIRE(fd > 0);

	// Do fstat and stat, and make sure both results are equal
	struct stat st;
	struct stat st2;
	REQUIRE(fstat(fd, &st) == 0);
	REQUIRE(st.st_size > 0);
	REQUIRE(stat(input, &st2) == 0);
	REQUIRE(memcmp(&st, &st2, sizeof(struct stat)) == 0);

	// Read all the file
	char* buf = new char[st.st_size + 1];
	REQUIRE(read(fd, buf, st.st_size) == st.st_size);
	buf[st.st_size] = 0;
	REQUIRE(strcmp(buf, "hello world1\nhello world2") == 0);

	// Read second line having cursor at the beginning
	REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	off_t offset = 13;
	size_t size = st.st_size - offset;
	REQUIRE(pread64(fd, buf, size, offset) == size);
	buf[size] = 0;
	REQUIRE(strcmp(buf, "hello world2") == 0);

	// Check cursor is still at the beginning
	REQUIRE(read(fd, buf, offset) == offset);
	buf[offset] = 0;
	REQUIRE(strcmp(buf, "hello world1\n") == 0);

	// Set cursor at the end and past end and try to read
	REQUIRE(lseek(fd, 0, SEEK_END) == st.st_size);
	REQUIRE(read(fd, buf, st.st_size) == 0);
	REQUIRE(lseek(fd, 10, SEEK_END) == st.st_size + 10);
	REQUIRE(read(fd, buf, st.st_size) == 0);

	// Move cursor around to check lseek
	REQUIRE(lseek(fd, 1234, SEEK_SET) == 1234);
	REQUIRE(lseek(fd, -1, SEEK_CUR) == 1233);
	REQUIRE(lseek(fd, -1, SEEK_END) == st.st_size - 1);
	REQUIRE(lseek(fd, -st.st_size, SEEK_CUR) == -1);
	REQUIRE(errno == EINVAL);
	REQUIRE(lseek(fd, -123, SEEK_SET) == -1);
	REQUIRE(errno == EINVAL);

	// Close file and make sure we can't do anything anymore
	REQUIRE(close(fd) == 0);
	REQUIRE(read(fd, buf, st.st_size) == -1);
	REQUIRE(errno == EBADF);
	REQUIRE(pread64(fd, buf, st.st_size, 0) == -1);
	REQUIRE(errno == EBADF);
	REQUIRE(lseek(fd, 0, SEEK_SET) == -1);
	REQUIRE(errno == EBADF);
	REQUIRE(fstat(fd, &st) == -1);
	REQUIRE(errno == EBADF);
	delete[] buf;
}

TEST_CASE("read not readable") {
	int fd = open(input, O_WRONLY);
	REQUIRE(fd > 0);
	REQUIRE(read_and_check_first_five_bytes(fd) == -1);
	REQUIRE(errno == EBADF);
	REQUIRE(close(fd) == 0);
}