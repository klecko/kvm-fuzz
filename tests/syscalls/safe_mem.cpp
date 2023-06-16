#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/random.h>
#include "common.h"

void* kernel_addr = (void*)0xffffffff80202000;
void* unmapped_addr = (void*)0x923848348000; // some random addr

void test_addr_read(int fd, void* addr) {
	REQUIRE(read(fd, addr, 1) == -1);
	REQUIRE(errno == EFAULT);
}

TEST_CASE("UserSlice fromFlat") {
	int fd = open(input, O_RDONLY);
	REQUIRE(fd > 0);

	test_addr_read(fd, kernel_addr);
	test_addr_read(fd, NULL);
	test_addr_read(fd, unmapped_addr);
	test_addr_read(fd, (void*)&read);

	REQUIRE(close(fd) == 0);
}

void test_addr_writev(void* addr) {
	struct iovec iovecs[1] = {{.iov_base = addr, .iov_len = 10}};
	REQUIRE(writev(STDOUT_FILENO, iovecs, 1) == -1);
	REQUIRE(errno == EFAULT);
}

TEST_CASE("UserSlice fromSlice") {
	test_addr_writev(kernel_addr);
	test_addr_writev(NULL);
	test_addr_writev(unmapped_addr);
	// we don't do the &read one because writev doesnt require writable memory,
	// so it would be valid
}

void test_addr_sysinfo(void* addr) {
	REQUIRE(sysinfo((struct sysinfo*)addr) == -1);
	REQUIRE(errno == EFAULT);
}

TEST_CASE("UserPtr fromFlat") {
	test_addr_sysinfo(kernel_addr);
	test_addr_sysinfo(NULL);
	test_addr_sysinfo(unmapped_addr);
	test_addr_sysinfo((void*)&read);
}

TEST_CASE("UserPtr fromPtr") {
	// fromPtr is not used anywhere at the kernel before being sanitized
	// by other methods like UserSlice.fromFlat.
}