#define _GNU_SOURCE
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

void init_memory() {
	// Get ownership of the physical memory
	ASSERT(g_next_frame_alloc == 0, "double init_memory ?");
	hc_get_mem_info((void**)&g_next_frame_alloc, &g_memory_length);
}

uintptr_t alloc_frame() {
	ASSERT(g_next_frame_alloc != 0, "memory has not been initialized");

	// Check if there's a free frame we can return
	if (!g_free_frames.empty()) {
		uintptr_t ret = g_free_frames.top();
		g_free_frames.pop();
		return ret;
	}

	// Check if we are OOM and return a new frame
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

size_t amount_free_memory() {
	ASSERT(g_next_frame_alloc != 0, "memory has not been initialized");
	size_t free_memory = g_memory_length - g_next_frame_alloc;
	size_t reused_memory = g_free_frames.size() * PAGE_SIZE;
	return free_memory + reused_memory;
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
	// Check if there's enough memory so we panic here instead of in
	// alloc_frame in case of OOM
	ASSERT(enough_free_memory(len), "OOM %p %lu %p", addr, len, flags);
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

bool is_range_free(void* addr, size_t len) {
	PageWalker pages(addr, len);
	do {
		if (pages.is_allocated())
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

bool enough_free_memory(size_t length) {
	// We don't want to use all of our memory: let's have some margin for us.
	// Also, when allocating memory we also need to allocate frames for page
	// directory entries.
	// FIXME: This doesn't guarantee having enough memory in all cases
	// FIXME: multiplication overflow?
	return Mem::Phys::amount_free_memory() > length*1.25;
}

} // namespace Virt
} // namespace Mem