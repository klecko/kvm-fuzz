#include "pmm.h"
#include "stack"
#include "x86/page_table.h"
#include "x86/asm.h"

namespace PMM {

static uintptr_t g_physmap_vaddr;
static uintptr_t g_next_frame_alloc;
static size_t g_memory_length;
static stack<uintptr_t> g_free_frames;
static size_t g_frames_allocated;

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

size_t memory_length() {
	return g_memory_length;
}

uintptr_t alloc_frame() {
	ASSERT(g_next_frame_alloc != 0, "memory has not been initialized");

	// Check if there's a free frame we can return
	if (!g_free_frames.empty()) {
		uintptr_t ret = g_free_frames.top();
		g_free_frames.pop();
		g_frames_allocated++;
		return ret;
	}

	// We need to allocate a new frame. First, check if we are OOM
	if (g_next_frame_alloc > g_memory_length - PAGE_SIZE)
		return 0;
	uintptr_t ret = g_next_frame_alloc;
	g_next_frame_alloc += PAGE_SIZE;
	g_frames_allocated++;
	return ret;
}

bool alloc_frames(size_t n, vector<uintptr_t>& frames) {
	frames.clear();

	// Check if there are enough free frames. We must also count those required
	// for the vector.
	size_t frames_required_for_vector = 1 + (n*sizeof(uintptr_t))/PAGE_SIZE;
	if (amount_free_frames() < n + frames_required_for_vector)
		return false;

	// Reserve exactly the number of slots we're going to use
	frames.reserve(n);

	// Allocate frames
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
	ASSERT(g_physmap_vaddr, "PMM not initialized");
	return (void*)(g_physmap_vaddr + phys);
}

uintptr_t virt_to_phys(void* virt) {
	uintptr_t p = (uintptr_t)virt;
	ASSERT(g_physmap_vaddr <= p && p < g_physmap_vaddr + g_memory_length,
	       "vaddr %p doesn't belong to physmap region", p);
	return p - g_physmap_vaddr;
}

uintptr_t dup_frame(uintptr_t frame) {
	uintptr_t copy = alloc_frame();
	if (!copy)
		return 0;
	memcpy(phys_to_virt(copy), phys_to_virt(frame), PAGE_SIZE);
	return copy;
}

size_t amount_free_frames() {
	size_t reused_frames = g_free_frames.size();
	size_t new_frames = (g_memory_length - g_next_frame_alloc)/PAGE_SIZE;
	return reused_frames + new_frames;
}

size_t frames_allocated() {
	return g_frames_allocated;
}

}