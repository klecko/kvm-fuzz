#include "mmu.h"

class Mmu::PageWalker {
public:
	PageWalker(vaddr_t vaddr, Mmu& mmu);

	// Range page walker
	PageWalker(vaddr_t start, vsize_t len, Mmu& mmu);

	vaddr_t start();
	vsize_t len();

	// Physical address of the PTE of the current page
	paddr_t pte();

	// Content of `pte()`. Note the result is a physical address with some bits
	// set corresponding to page flags
	paddr_t pte_val();

	// Current virtual address (virtual address of current page, with
	// offset in case it is the first one)
	vaddr_t vaddr();

	// Current physical address (physichal address of current page, with
	// offset in case it's the first one)
	paddr_t paddr();

	// Offset from the beginning to current virtual address
	vsize_t offset();

	// Memory length from current address until the end of the page, or
	// until the end of range if it's the last page of a range page walker
	vsize_t page_size();

	// Get and set current page flags
	uint64_t flags();
	void set_flags(uint64_t flags);

	// Alloc a frame for current page. Fail if it has already a frame
	void alloc_frame(uint64_t flags);

	// Returns whether current virtual address is mapped or not
	bool is_mapped();

	// Advance to the next page, allocating page table entries when needed.
	// In case of range page walkers, returns whether the new page is in
	// given range. Normal page walkers always return false
	bool next();

	// Advance to the next mapped page. This method does not allocate
	// page table entries
	bool next_mapped();

private:
	static const int FLAGS;
	vaddr_t  m_start;
	vsize_t  m_len;
	Mmu&     m_mmu;
	vsize_t  m_offset;
	paddr_t  m_ptl3;
	paddr_t  m_ptl2;
	paddr_t  m_ptl1;
	uint64_t m_ptl4_i;
	uint64_t m_ptl3_i;
	uint64_t m_ptl2_i;
	uint64_t m_ptl1_i;

	void update_ptl3();
	void update_ptl2();
	void update_ptl1();
	void next_ptl4_entry();
	void next_ptl3_entry();
	void next_ptl2_entry();
	void next_ptl1_entry();
};