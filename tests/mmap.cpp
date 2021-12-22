#include <sys/mman.h>
#include <fcntl.h>
#include <cstring>
#include "common.h"

// mov rax, 0x1234; ret
const uint8_t shellcode[] = "\x48\xc7\xc0\x34\x12\x00\x00\xc3";

const int PAGE_SIZE = 0x1000;
const int prot = PROT_READ | PROT_WRITE;
const int flags = MAP_ANON | MAP_PRIVATE;
void* const kernel_addr = (void*)0xffffffffa1d0f000;

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
	uint8_t* p2 = (uint8_t*)mmap(p + PAGE_SIZE, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p2 == p + PAGE_SIZE);
	*p2 = 2;

	// Remap first page
	uint8_t* p3 = (uint8_t*)mmap(p, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p3 == p);
	REQUIRE(*p3 == 0);
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
	REQUIRE(errno == EINVAL);
}

TEST_CASE("mmap kernel") {
	void* p = mmap(kernel_addr, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p == MAP_FAILED);
	REQUIRE(errno == ENOMEM);

	REQUIRE(mprotect(kernel_addr, PAGE_SIZE, PROT_NONE) == -1);
	REQUIRE(errno == ENOMEM);

	REQUIRE(munmap(kernel_addr, PAGE_SIZE) == -1);
	REQUIRE(errno == EINVAL);
}

TEST_CASE("mmap kernel hint") {
	// Hint should be ignored
	void* p = mmap(kernel_addr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	REQUIRE(p != kernel_addr);
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
}

TEST_CASE("mmap not open file") {
	void* p = mmap(nullptr, PAGE_SIZE, prot, MAP_PRIVATE, 1234, 0);
	REQUIRE(p == MAP_FAILED);
	REQUIRE(errno == EBADF);
}

TEST_CASE("mmap shared and private") {
	// Both shared and private
	void* p = mmap(nullptr, PAGE_SIZE, prot, flags | MAP_SHARED, -1, 0);
	REQUIRE(p == MAP_FAILED);
	REQUIRE(errno == EINVAL);

	// Not shared and not private
	p = mmap(nullptr, PAGE_SIZE, prot, MAP_ANONYMOUS, -1, 0);
	REQUIRE(p == MAP_FAILED);
	REQUIRE(errno == EINVAL);
}

TEST_CASE("mmap reuse address") {
	void* p1 = mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p1 != MAP_FAILED);

	REQUIRE(munmap(p1, PAGE_SIZE) == 0);

	void* p2 = mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p2 == p1);

	REQUIRE(munmap(p2, PAGE_SIZE) == 0);
}

TEST_CASE("mmap prot none") {
	// TODO: when multitasking, fork and check child dies when accessing
	void* p = mmap(nullptr, PAGE_SIZE, PROT_NONE, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	REQUIRE(munmap(p, PAGE_SIZE) == 0);

	p = mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	REQUIRE(mprotect(p, PAGE_SIZE, PROT_NONE) == 0);
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
}

TEST_CASE("mmap hint") {
	// Map two pages, unmap one of them
	uint8_t* p1 = (uint8_t*)mmap(nullptr, 2*PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p1 != MAP_FAILED);
	REQUIRE(munmap(p1 + PAGE_SIZE, PAGE_SIZE) == 0);

	// Hint not mapped
	uint8_t* p2 = (uint8_t*)mmap(p1 + PAGE_SIZE, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p2 == p1 + PAGE_SIZE);

	// Hint mapped
	uint8_t* p3 = (uint8_t*)mmap(p1 + PAGE_SIZE, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p3 != MAP_FAILED);
	REQUIRE(p3 != p1 + PAGE_SIZE);

	REQUIRE(munmap(p1, PAGE_SIZE) == 0);
	REQUIRE(munmap(p2, PAGE_SIZE) == 0);
	REQUIRE(munmap(p3, PAGE_SIZE) == 0);
}

// This requires test mmap_hint to pass
bool is_mapped(void* page) {
	// Map with addr without MAP_FIXED and see if succeeds
	void* p = mmap(page, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p != MAP_FAILED);
	REQUIRE(munmap(p, PAGE_SIZE) == 0);
	return p != page;
}

TEST_CASE("munmap not mappped") {
	// We've got a mapped page, a hole of an unmapped page, and another page
	uint8_t* p1 = (uint8_t*)mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p1 != MAP_FAILED);
	uint8_t* p2 = (uint8_t*)mmap(p1 + 2*PAGE_SIZE, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p2 == p1 + 2*PAGE_SIZE);

	// Munmap the three pages
	REQUIRE(munmap(p1, 3*PAGE_SIZE) == 0);

	// Make sure both pages have actually been unmapped
	REQUIRE(!is_mapped(p1));
	REQUIRE(!is_mapped(p1 + 2*PAGE_SIZE));
}

TEST_CASE("mmap partial") {
	// We've got a mapped page. Attempting to map two pages at the page before
	// it results in the page before it mapped. However, as the second page is
	// already mapped, the two pages end up being mapped somewhere else.
	uint8_t* p1 = (uint8_t*)mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p1 != MAP_FAILED);
	uint8_t* p2 = (uint8_t*)mmap(p1 - PAGE_SIZE, 2*PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p2 != MAP_FAILED);

	// p2 is not at p1 - PAGE_SIZE, but that page is now mapped (!!)
	REQUIRE(p2 != p1 - PAGE_SIZE);
	REQUIRE(is_mapped(p1 - PAGE_SIZE));
	REQUIRE(munmap(p1, PAGE_SIZE) == 0);
	REQUIRE(munmap(p2, 2*PAGE_SIZE) == 0);
}

TEST_CASE("mmap partial2") {
	// We've got a mapped page, a hole of an unmapped page, and another page
	uint8_t* p1 = (uint8_t*)mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p1 != MAP_FAILED);
	uint8_t* p2 = (uint8_t*)mmap(p1 + 2*PAGE_SIZE, PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p2 == p1 + 2*PAGE_SIZE);

	// Mapping 3 pages here shouldn't map the page in the middle
	uint8_t* p3 = (uint8_t*)mmap(p1, 3*PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p3 != MAP_FAILED);
	REQUIRE(p3 != p1);
	REQUIRE(!is_mapped(p1 + PAGE_SIZE));

	REQUIRE(munmap(p1, PAGE_SIZE) == 0);
	REQUIRE(munmap(p2, PAGE_SIZE) == 0);
	REQUIRE(munmap(p3, 3*PAGE_SIZE) == 0);
}

TEST_CASE("mmap partial fixed") {
	uint8_t* p1 = (uint8_t*)mmap(nullptr, PAGE_SIZE, prot, flags, -1, 0);
	REQUIRE(p1 != MAP_FAILED);
	*p1 = 1;
	uint8_t* p2 = (uint8_t*)mmap(p1 - PAGE_SIZE, 2*PAGE_SIZE, prot, flags | MAP_FIXED, -1, 0);
	REQUIRE(p2 == p1 - PAGE_SIZE);
	REQUIRE(*p1 == 0);
	REQUIRE(munmap(p2, 2*PAGE_SIZE) == 0);
	REQUIRE(!is_mapped(p1));
}

size_t get_system_available_memory() {
	assert(sysconf(_SC_PAGE_SIZE) == PAGE_SIZE);
	return sysconf(_SC_AVPHYS_PAGES) * PAGE_SIZE;
}

TEST_CASE("mmap ENOMEM") {
	size_t size = get_system_available_memory() * 10;
	void* p = mmap(nullptr, size, prot, flags, -1, 0);
	REQUIRE(p == MAP_FAILED);
	REQUIRE(errno == ENOMEM);
}