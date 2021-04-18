#include "heap.h"
#include "vmm.h"
#include "x86/page_table.h"

Heap::Heap()
	: m_base(0)
	, m_used(0)
	, m_size(0)
{
}

Heap::Heap(void* base)
	: Heap()
{
	init(base);
}

void Heap::init(void* base) {
	m_base = (uint8_t*)base;
	ASSERT(more(INITIAL_PAGES), "failed to init kernel heap");
}

bool Heap::more(size_t n_pages) {
	if (!VMM::alloc_pages(m_base + m_size, n_pages))
		return false;
	m_size += n_pages * PAGE_SIZE;
	return true;
}

size_t Heap::free_bytes() {
	return m_size - m_used;
}

void* Heap::alloc(size_t size) {
	ASSERT(m_base, "allocating on not initialized heap");

	if (size > free_bytes()) {
		size_t n_pages = PAGE_CEIL(size - free_bytes()) / PAGE_SIZE;
		ASSERT(more(n_pages), "OOM kernel heap");
	}

	void* ret = m_base + m_used;
	m_used += size;
	ASSERT(m_used <= m_size, "we fucked up: %p %p", m_used, m_size);
	return ret;
}

void Heap::free(void* ptr) {
}

