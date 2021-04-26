#include <sys/mman.h>
#include <fcntl.h>
#include <cstring>
#include "common.h"

// mov rax, 0x1234; ret
const uint8_t shellcode[] = "\x48\xc7\xc0\x34\x12\x00\x00\xc3";

const int PAGE_SIZE = 0x1000;
const int prot = PROT_READ | PROT_WRITE;
const int flags = MAP_ANON | MAP_PRIVATE;

TEST_CASE("mmap anon write") {
	uint8_t* p = (uint8_t*)mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	*p = 1;
	*(p + 0xFFF) = 1;
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
}

TEST_CASE("mmap anon exec") {
	void* p = mmap(nullptr, PAGE_SIZE, prot | PROT_EXEC, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	memcpy(p, shellcode, sizeof(shellcode));
	REQUIRE(((int(*)(void))p)() == 0x1234);
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
}

TEST_CASE("mmap OOM") {
	void* p = mmap(nullptr, SIZE_MAX, prot, flags, -1, 0);
	REQUIRE(p == MAP_FAILED);
	REQUIRE(errno == ENOMEM);
}

TEST_CASE("mmap file") {
	int fd = open(input, O_RDONLY);
	REQUIRE(fd != -1);
	char* p = (char*)mmap(nullptr, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	REQUIRE(p != MAP_FAILED);
	REQUIRE(strcmp(p, "hello world1\nhello world2") == 0);
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
}

TEST_CASE("mmap fixed") {
	// First mapping
	uint8_t* p = (uint8_t*)mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	*p = 1;

	// Map one page further
	void* p2 = mmap(p + PAGE_SIZE, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p2 == p + PAGE_SIZE);
	*(uint8_t*)p2 = 2;

	// Remap first page
	void* p3 = mmap(p, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p3 == p);
	*(uint8_t*)p3 = 3;

	// I don't know if these should be required, as they depend on mmap_min_addr
	// void* p4 = mmap(nullptr, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	// REQUIRE(p4 == MAP_FAILED);
	// void* p5 = mmap((void*)PAGE_SIZE, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	// REQUIRE(p5 == MAP_FAILED);

	// Mmap not aligned
	void* p6 = mmap(p + PAGE_SIZE/2, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p6 == MAP_FAILED);
	REQUIRE(errno == EINVAL);

	// Attempt to munmap not aligned
	REQUIRE(munmap(p + PAGE_SIZE/2, PAGE_SIZE/2) == -1);
	REQUIRE(errno == EINVAL);

	// Munmaps
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
	REQUIRE(munmap(p2, PAGE_SIZE) == 0);
	REQUIRE(munmap(p3, PAGE_SIZE) == 0); // munmap twice is not an error
	REQUIRE(munmap(nullptr, PAGE_SIZE) == 0); // munmap not mapped addr neither
	REQUIRE(munmap((void*)1, PAGE_SIZE) == -1); // but address must be aligned
}