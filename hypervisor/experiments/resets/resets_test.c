#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

void err(const char* msg) {
	puts(msg);
	exit(EXIT_FAILURE);
}

void fuzz_start() {}
void fuzz_end() {}

int main(int argc, char** argv) {
	if (argc != 2) err("args");

	int n = atoi(argv[1]);
	char* p = (n ? mmap(NULL, n*0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, -1, 0) : NULL);
	if (p == MAP_FAILED) err("mmap");

	fuzz_start();
	for (int i = 0; i < n; i++) {
		p[i*0x1000] = 1;
	}
	fuzz_end();
}
