#include "page_walker.h"
#include "kvm_aux.h"

using namespace std;

const int Mmu::PageWalker::FLAGS = PDE64_PRESENT | PDE64_RW | PDE64_USER;

Mmu::PageWalker::PageWalker(vaddr_t vaddr, Mmu& mmu)
	: m_start(vaddr)
	, m_len(0)
	, m_mmu(mmu)
	, m_offset(0)
	, m_ptl4_i(PTL4_INDEX(vaddr))
	, m_ptl3_i(PTL3_INDEX(vaddr))
	, m_ptl2_i(PTL2_INDEX(vaddr))
	, m_ptl1_i(PTL1_INDEX(vaddr))
{
	update_ptl3();
	update_ptl2();
	update_ptl1();
}

Mmu::PageWalker::PageWalker(vaddr_t start, vsize_t len, Mmu& mmu)
	: PageWalker(start, mmu)
{
	m_len = len;
}

vaddr_t Mmu::PageWalker::start() {
	return m_start;
}

vaddr_t Mmu::PageWalker::len() {
	return m_len;
}

paddr_t* Mmu::PageWalker::pte() {
	return &m_ptl1[m_ptl1_i];
}

vsize_t Mmu::PageWalker::offset() {
	return m_offset;
}

vaddr_t Mmu::PageWalker::vaddr() {
	return m_start + m_offset;
}

paddr_t Mmu::PageWalker::paddr() {
	ASSERT(*pte(), "Trying to translate not mapped vaddr: 0x%lx", vaddr());
	return (*pte() & PTL1_MASK) + PAGE_OFFSET(vaddr());
}

vsize_t Mmu::PageWalker::page_size() {
	vsize_t ret = PAGE_SIZE - PAGE_OFFSET(vaddr());
	if (m_len && m_offset < m_len)
		ret = min(ret, m_len - m_offset);
	return ret;
}

uint64_t Mmu::PageWalker::flags() {
	ASSERT(*pte(), "Trying to get flags of not mapped vaddr: 0x%lx", vaddr());
	return PAGE_OFFSET(*pte()); // FIXME NX
}

void Mmu::PageWalker::set_flags(uint64_t flags) {
	ASSERT(*pte(), "Trying to set flags to not mapped vaddr: 0x%lx", vaddr());
	ASSERT(PAGE_OFFSET(flags) == flags, "bad page flags: %lx", flags);
	*pte() = (*pte() & PTL1_MASK) | flags;
}

void Mmu::PageWalker::add_flags(uint64_t flags) {
	ASSERT(*pte(), "Trying to add flags to not mapped vaddr: 0x%lx", vaddr());
	ASSERT(PAGE_OFFSET(flags) == flags, "bad page flags: %lx", flags);
	*pte() |= flags;
}

void Mmu::PageWalker::clear_flags(uint64_t flags) {
	ASSERT(*pte(), "Trying to clear flags to not mapped vaddr: 0x%lx", vaddr());
	ASSERT(PAGE_OFFSET(flags) == flags, "bad page flags: %lx", flags);
	*pte() &= ~flags;
}

void Mmu::PageWalker::alloc_frame(uint64_t flags) {
	ASSERT(!*pte(), "vaddr already mapped: 0x%lx", vaddr());
	*pte() = m_mmu.alloc_frame() | flags;
	dbgprintf("Alloc frame: 0x%lx mapped to 0x%lx with flags 0x%lx\n",
	          vaddr(), *pte() & PTL1_MASK, flags);
}

bool Mmu::PageWalker::is_mapped() {
	return *pte() != 0;
}

bool Mmu::PageWalker::next() {
	// Advance one PTE, update current offset and return whether there are more
	// pages left
	next_ptl1_entry();

	m_offset += PAGE_SIZE - PAGE_OFFSET(vaddr());

	return m_offset < m_len;
}

void Mmu::PageWalker::update_ptl3() {
	if (!m_mmu.m_ptl4[m_ptl4_i]) {
		m_mmu.m_ptl4[m_ptl4_i] = m_mmu.alloc_frame() | FLAGS;
	}
	m_ptl3 = (paddr_t*)(m_mmu.m_memory + (m_mmu.m_ptl4[m_ptl4_i] & PTL1_MASK));
}

void Mmu::PageWalker::update_ptl2() {
	if (!m_ptl3[m_ptl3_i]) {
		m_ptl3[m_ptl3_i] = m_mmu.alloc_frame() | FLAGS;
	}
	m_ptl2 = (paddr_t*)(m_mmu.m_memory + (m_ptl3[m_ptl3_i] & PTL1_MASK));
}

void Mmu::PageWalker::update_ptl1() {
	if (!m_ptl2[m_ptl2_i]) {
		m_ptl2[m_ptl2_i] = m_mmu.alloc_frame() | FLAGS;
	}
	m_ptl1 = (paddr_t*)(m_mmu.m_memory + (m_ptl2[m_ptl2_i] & PTL1_MASK));
}

void Mmu::PageWalker::next_ptl4_entry() {
	m_ptl4_i++;
	ASSERT(m_ptl4_i != PTRS_PER_PTL4, "PageWalker: OOB?");
	update_ptl3();
}

void Mmu::PageWalker::next_ptl3_entry() {
	m_ptl3_i++;
	if (m_ptl3_i == PTRS_PER_PTL3) {
		m_ptl3_i = 0;
		next_ptl4_entry();
	}
	update_ptl2();
}

void Mmu::PageWalker::next_ptl2_entry() {
	m_ptl2_i++;
	if (m_ptl2_i == PTRS_PER_PTL2) {
		m_ptl2_i = 0;
		next_ptl3_entry();
	}
	update_ptl1();
}

void Mmu::PageWalker::next_ptl1_entry() {
	m_ptl1_i++;
	if (m_ptl1_i == PTRS_PER_PTL1) {
		m_ptl1_i = 0;
		next_ptl2_entry();
	}
}

bool Mmu::PageWalker::next_mapped() {
	TODO
}