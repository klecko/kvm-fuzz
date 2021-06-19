#include "page_table.h"
#include "x86/asm.h"
#include "mem/pmm.h"

PageTable::PageTable()
	: m_ptl4(nullptr)
{
}

PageTable::PageTable(uintptr_t ptl4_paddr)
	: PageTable()
{
	set(ptl4_paddr);
}

void PageTable::set(uintptr_t ptl4_paddr) {
	m_ptl4 = (PageTableLevel4Entry*)PMM::phys_to_virt(ptl4_paddr);
}

bool PageTable::map(uintptr_t virt, uintptr_t phys, uint64_t page_flags,
                    bool discard_already_mapped)
{
	ASSERT(virt, "mapping address 0 >:(");
	PageTableEntry* pte = ensure_pte(virt);
	if (!pte)
		return false;

	if (pte->is_present()) {
		if (discard_already_mapped) {
			PMM::free_frame(pte->frame_base());
		} else {
			dbgprintf("attempt to map already mapped %p\n", virt);
			return false;
		}
	}

	pte->set_frame_base(phys & PHYS_MASK);
	pte->set_flags(page_flags);
	pte->set_present(true);
	flush_tlb_entry(virt);
	// dbgprintf("mapped %p to %p with flags %p", virt, phys, page_flags);
	return true;
}

bool PageTable::unmap(uintptr_t virt, bool ignore_not_mapped) {
	PageTableEntry* pte = ensure_pte(virt);
	if (!pte)
		return false;

	// If the page was not mapped, that's a fail only if `ignore_not_mapped` was
	// not set
	if (!pte->is_present())
		return ignore_not_mapped;

	PMM::free_frame(pte->frame_base());
	pte->clear();
	flush_tlb_entry(virt);
	return true;
}

PageTableEntry* PageTable::ensure_pte(uintptr_t page_addr) {
	ASSERT(m_ptl4, "uninitialized page table");
	size_t ptl4_i = PTL4_INDEX(page_addr);
	PageTableLevel4Entry& ptl4_entry = m_ptl4[ptl4_i];
	if (!ensure_entry_present(ptl4_entry))
		return nullptr;

	size_t ptl3_i = PTL3_INDEX(page_addr);
	PageTableLevel3Entry* ptl3 = page_table_pointed_by(ptl4_entry);
	PageTableLevel3Entry& ptl3_entry = ptl3[ptl3_i];
	if (!ensure_entry_present(ptl3_entry))
		return nullptr;

	size_t ptl2_i = PTL2_INDEX(page_addr);
	PageTableLevel2Entry* ptl2 = page_table_pointed_by(ptl3_entry);
	PageTableLevel2Entry& ptl2_entry = ptl2[ptl2_i];
	if (!ensure_entry_present(ptl2_entry))
		return nullptr;

	size_t ptl1_i = PTL1_INDEX(page_addr);
	PageTableEntry* ptl1 = page_table_pointed_by(ptl2_entry);
	PageTableEntry& ptl1_entry = ptl1[ptl1_i];

	return &ptl1_entry;
}

PageTableEntry* PageTable::page_table_pointed_by(PageTableEntry& entry) {
	return (PageTableEntry*)PMM::phys_to_virt(entry.frame_base());
}

bool PageTable::ensure_entry_present(PageTableEntry& entry) {
	if (!entry.is_present()) {
		uintptr_t frame = PMM::alloc_frame();
		if (!frame)
			return false;
		entry.set_frame_base(frame);
		entry.set_present(true);
		entry.set_writable(true);
		entry.set_user(true); // ?
		flush_tlb_entry((uintptr_t)PMM::phys_to_virt(frame)); // ???
	}
	return true;
}

void PageTable::load() {
	ASSERT(m_ptl4, "uninitialized page table");
	wrcr3((uintptr_t)m_ptl4);
}