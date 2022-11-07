#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

const char input[] = "./tests/input_hello_world";

void error(const char* msg) {
	perror(msg);
	exit(EXIT_FAILURE);
}

__attribute_noinline__
void test_me(char* buf) {
	buf[0] = 0; // just do something so we are not optimized away
}

int main() {
	int fd = open(input, O_RDONLY);
	if (fd < 0)
		error("open");

	char buf[6];
	ssize_t bytes_read = read(fd, buf, sizeof(buf)-1);
	if (bytes_read != sizeof(buf)-1)
		error("read");
	buf[sizeof(buf)-1] = 0;

	test_me(buf);

	close(fd);
}