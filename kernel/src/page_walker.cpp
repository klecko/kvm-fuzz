#include "page_walker.h"
#include "asm.h"
#include "mem.h"


PageWalker::PageWalker(void* start, size_t len)
	: m_start((uintptr_t)start)
	, m_len(len)
	, m_offset(0)
	, m_ptl4((uintptr_t*)Mem::Phys::virt(rdcr3()))
	, m_ptl4_i(PTL4_INDEX(m_start))
	, m_ptl3_i(PTL3_INDEX(m_start))
	, m_ptl2_i(PTL2_INDEX(m_start))
	, m_ptl1_i(PTL1_INDEX(m_start))
{
	ASSERT((m_start & PTL1_MASK) == m_start, "not aligned start: 0x%lx", m_start);
	ASSERT((m_len & PTL1_MASK) == m_len, "not aligned len: 0x%lx", m_len);
	update_ptl3();
	update_ptl2();
	update_ptl1();
}

void PageWalker::alloc_frame(uint64_t flags) {
	ASSERT(!*pte(), "address already mapped: 0x%lx to 0x%lx", addr(), *pte());
	*pte() = Mem::Phys::alloc_frame() | flags;
}

void PageWalker::free_frame() {
	ASSERT(*pte(), "address not mapped: 0x%lx", addr());
	Mem::Phys::free_frame(*pte() & PTL1_MASK);
	*pte() = 0;
}

void PageWalker::set_flags(uint64_t flags) {
	ASSERT(*pte(), "address not mapped: 0x%lx", addr());
	*pte() = (*pte() & PTL1_MASK) | flags;
}

bool PageWalker::next() {
	// Advance one PTE, update current offset and return whether there are more
	// pages left
	next_ptl1_entry();

	m_offset += PAGE_SIZE;

	// If there are more pages left in the range of memory specified, check
	// we are not at the end of the memory space
	bool ret = m_offset < m_len;
	if (ret)
		ASSERT(m_ptl4_i != PTRS_PER_PTL4, "PageWalker: OOB?");
	return ret;
}

uintptr_t PageWalker::addr() {
	return m_start + m_offset;
}

uintptr_t* PageWalker::pte() {
	return &m_ptl1[m_ptl1_i];
}

const int PAGE_TABLE_ENTRIES_FLAGS = PDE64_PRESENT | PDE64_RW | PDE64_USER;
void PageWalker::update_ptl3() {
	if (!m_ptl4[m_ptl4_i]) {
		m_ptl4[m_ptl4_i] = Mem::Phys::alloc_frame() | PAGE_TABLE_ENTRIES_FLAGS;
	}
	m_ptl3 = (uintptr_t*)Mem::Phys::virt((m_ptl4[m_ptl4_i] & PTL1_MASK));
}

void PageWalker::update_ptl2() {
	if (!m_ptl3[m_ptl3_i]) {
		m_ptl3[m_ptl3_i] = Mem::Phys::alloc_frame() | PAGE_TABLE_ENTRIES_FLAGS;
	}
	m_ptl2 = (uintptr_t*)Mem::Phys::virt((m_ptl3[m_ptl3_i] & PTL1_MASK));
}

void PageWalker::update_ptl1() {
	if (!m_ptl2[m_ptl2_i]) {
		m_ptl2[m_ptl2_i] = Mem::Phys::alloc_frame() | PAGE_TABLE_ENTRIES_FLAGS;
	}
	m_ptl1 = (uintptr_t*)Mem::Phys::virt((m_ptl2[m_ptl2_i] & PTL1_MASK));
}

void PageWalker::next_ptl4_entry() {
	m_ptl4_i++;
	update_ptl3();
}

void PageWalker::next_ptl3_entry() {
	m_ptl3_i++;
	if (m_ptl3_i == PTRS_PER_PTL3) {
		m_ptl3_i = 0;
		next_ptl4_entry();
	}
	update_ptl2();
}

void PageWalker::next_ptl2_entry() {
	m_ptl2_i++;
	if (m_ptl2_i == PTRS_PER_PTL2) {
		m_ptl2_i = 0;
		next_ptl3_entry();
	}
	update_ptl1();
}

void PageWalker::next_ptl1_entry() {
	m_ptl1_i++;
	if (m_ptl1_i == PTRS_PER_PTL1) {
		m_ptl1_i = 0;
		next_ptl2_entry();
	}
}