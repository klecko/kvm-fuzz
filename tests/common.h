#define CATCH_CONFIG_FAST_COMPILE
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#define CATCH_CONFIG_COLOUR_NONE
#include <cstring>
#include <unistd.h>
#include "catch.hpp"

const char input[] = "../tests/input_hello_world";

__attribute__((warn_unused_result))
inline int read_and_check_first_five_bytes(int fd, char* buf) {
	if (read(fd, buf, 5) != 5)
		return -1;
	buf[5] = 0;
	if (strcmp(buf, "hello") != 0)
		return -2;
	return 0;
}

__attribute__((warn_unused_result))
inline int read_and_check_next_seven_bytes(int fd, char* buf) {
	if (read(fd, buf, 7) != 7)
		return -1;
	buf[8] = 0;
	if (strcmp(buf, " world1") != 0)
		return -2;
	return 0;
}

