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

uintptr_t alloc_frame(bool assert_not_oom) {
	// Get ownership of the physical memory
	if (g_next_frame_alloc == 0) {
		hc_get_mem_info((void**)&g_next_frame_alloc, &g_memory_length);
	}

	// Check if there's a free frame we can return
	if (!g_free_frames.empty()) {
		uintptr_t ret = g_free_frames.top();
		g_free_frames.pop();
		return ret;
	}

	// Check if we are OOM
	if (g_next_frame_alloc > g_memory_length - PAGE_SIZE) {
		ASSERT(!assert_not_oom, "OOM");
		return 0;
	}

	// Return a new frame
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

void* alloc(size_t len, uint64_t flags, bool assert_not_oom) {
	// Kernel should use kmalloc for now
	ASSERT(flags & PDE64_USER, "kernel memory allocation?");
	g_next_user_alloc -= len;
	bool success = alloc((void*)g_next_user_alloc, len, flags, assert_not_oom);
	return (success ? (void*)g_next_user_alloc : NULL);
}

bool alloc(void* addr, size_t len, uint64_t flags, bool assert_not_oom) {
	if (!(flags & PDE64_PROTNONE))
		flags |= PDE64_PRESENT;

	bool success;
	PageWalker pages(addr, len);
	do {
		success = pages.alloc_frame(flags, assert_not_oom);
	} while (pages.next() && success);

	size_t offset = pages.offset();
	if (!success && offset > 0) {
		// Free every page mapped
		PageWalker pages_mapped(addr, offset - PAGE_SIZE);
		do {
			pages_mapped.free_frame();
		} while (pages_mapped.next());
	}
	return success;
}

void* alloc_user_stack() {
	void* stack_top = (void*)(USER_STACK_ADDR - USER_STACK_SIZE);
	alloc(stack_top, USER_STACK_SIZE, PDE64_USER | PDE64_RW | PDE64_NX);
	return (void*)(USER_STACK_ADDR);
}

bool is_range_allocated(void* addr, size_t len) {
	PageWalker pages(addr, len);
	do {
		if (!pages.is_allocated())
			return false;
	} while (pages.next());
	return true;
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