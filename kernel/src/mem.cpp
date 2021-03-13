#define _GNU_SOURCE
#include <sys/mman.h>
#include "common.h"
#include "stack"
#include "mem.h"
#include "page_walker.h"

namespace Mem {

namespace Phys {

// Keep this the same as in hypervisor!
static const uintptr_t PHYSMAP_ADDR = 0xFFFFFF8000000000;
uintptr_t g_next_frame_alloc;
size_t    g_memory_length;
stack<uintptr_t> g_free_frames;

uintptr_t alloc_frame() {
	if (g_next_frame_alloc == 0) {
		hc_get_mem_info((void**)&g_next_frame_alloc, &g_memory_length);
	}
	if (!g_free_frames.empty()) {
		uintptr_t ret = g_free_frames.top();
		g_free_frames.pop();
		return ret;
	}
	ASSERT(g_next_frame_alloc <= g_memory_length - PAGE_SIZE, "OOM");
	uintptr_t ret = g_next_frame_alloc;
	g_next_frame_alloc += PAGE_SIZE;
	return ret;
}

void free_frame(uintptr_t frame) {
	// TODO Kappa
	ASSERT((frame & PTL1_MASK) == frame, "not aligned frame: %p", frame);
	memset(virt(frame), 0, PAGE_SIZE);
	g_free_frames.push(frame);
}

void* virt(uintptr_t phys) {
	return (void*)(phys + PHYSMAP_ADDR);
}

} // namespace Phys


namespace Virt {

static const uintptr_t USER_MAPPINGS_START_ADDR = 0x7FFFF7FFE000;
static const uintptr_t USER_STACK_ADDR          = 0x800000000000;
static const size_t    USER_STACK_SIZE          = 0x10000;
uintptr_t g_next_user_alloc = USER_MAPPINGS_START_ADDR;

void* alloc(size_t len, uint64_t flags) {
	// Kernel should use kmalloc for now
	ASSERT(flags & PDE64_USER, "kernel memory allocation?");
	g_next_user_alloc -= len;
	alloc((void*)g_next_user_alloc, len, flags);
	return (void*)g_next_user_alloc;
}

void alloc(void* addr, size_t len, uint64_t flags) {
	if (!(flags & PDE64_PROTNONE))
		flags |= PDE64_PRESENT;
	PageWalker pages(addr, len);
	do {
		pages.alloc_frame(flags);
	} while (pages.next());
}

void* alloc_user_stack() {
	void* stack_top = (void*)(USER_STACK_ADDR - USER_STACK_SIZE);
	alloc(stack_top, USER_STACK_SIZE, PDE64_USER | PDE64_RW | PDE64_NX);
	return (void*)(USER_STACK_ADDR);
}

void free(void* addr, size_t len) {
	PageWalker pages(addr, len);
	do {
		pages.free_frame();
	} while (pages.next());
}

void set_flags(void* addr, size_t len, uint64_t flags) {
	if (!(flags & PDE64_PROTNONE))
		flags |= PDE64_PRESENT;
	PageWalker pages(addr, len);
	do {
		pages.set_flags(flags);
	} while (pages.next());
}

} // namespace Virt
} // namespace Mem