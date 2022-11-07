#include <unistd.h>
#include <cstring>
#include "common.h"

TEST_CASE("stdin") {
	// Reading input from stdin
	printf("Stdin test\n");
	char buf[6];
	REQUIRE(read_and_check_first_five_bytes(STDIN_FILENO, buf) == 0);
}