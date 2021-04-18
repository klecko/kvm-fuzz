#include "pmm.h"
#include "stack"
#include "x86/page_table.h"
#include "x86/asm.h"

namespace PMM {

uintptr_t g_physmap_vaddr;
uintptr_t g_next_frame_alloc;
size_t g_memory_length;
stack<uintptr_t> g_free_frames;

void init() {
	// Get ownership of the physical memory
	ASSERT(g_next_frame_alloc == 0, "double init?");
	MemInfo info;
	hc_get_mem_info(&info);
	g_next_frame_alloc = (uintptr_t)info.mem_start;
	g_memory_length = info.mem_length;
	g_physmap_vaddr = (uintptr_t)info.physmap_vaddr;
	dbgprintf("PMM initialized\n");
}

uintptr_t alloc_frame() {
	ASSERT(g_next_frame_alloc != 0, "memory has not been initialized");

	// Check if there's a free frame we can return
	if (!g_free_frames.empty()) {
		uintptr_t ret = g_free_frames.top();
		g_free_frames.pop();
		return ret;
	}

	// We need to allocate a new frame. First, check if we are OOM
	if (g_next_frame_alloc > g_memory_length - PAGE_SIZE)
		return 0;
	uintptr_t ret = g_next_frame_alloc;
	g_next_frame_alloc += PAGE_SIZE;
	return ret;
}

bool alloc_frames(size_t n, vector<uintptr_t>& frames) {
	if (amount_free_frames() < n)
		return false;
	for (size_t i = 0; i < n; i++) {
		uintptr_t frame = alloc_frame();
		ASSERT(frame, "failed after ensuring there were enough frames?");
		frames.push_back(frame);
	}
	return true;
}

void free_frame(uintptr_t frame) {
	ASSERT((frame & PTL1_MASK) == frame, "not aligned frame: %p", frame);
	memset(phys_to_virt(frame), 0, PAGE_SIZE);
	g_free_frames.push(frame);
}


void* phys_to_virt(uintptr_t phys) {
	return (void*)(g_physmap_vaddr + phys);
}

size_t amount_free_frames() {
	size_t reused_frames = g_free_frames.size();
	size_t new_frames = (g_next_frame_alloc - g_memory_length)/PAGE_SIZE;
	return reused_frames + new_frames;
}

}