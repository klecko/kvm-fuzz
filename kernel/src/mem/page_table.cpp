#include "page_table.h"
#include "x86/asm.h"
#include "mem/pmm.h"
#include "mem/vmm.h"

PageTable::PageTable(bool create)
	: m_ptl4(nullptr)
{
	if (create) {
		uintptr_t frame = PMM::alloc_frame();
		ASSERT(frame, "OOM creating page table");
		set(frame);
		map_kernel();
	}
}

void PageTable::map_kernel() {
	const PageTable& kernel_page_table = VMM::kernel_page_table();
	m_ptl4[511] = kernel_page_table.m_ptl4[511];
}

// PageTable::PageTable(uintptr_t ptl4_paddr)
// 	: PageTable()
// {
// 	set(ptl4_paddr);
// }

void PageTable::set(uintptr_t ptl4_paddr) {
	m_ptl4 = (PageTableLevel4Entry*)PMM::phys_to_virt(ptl4_paddr);
}

void PageTable::set_current_cr3() {
	set(rdcr3());
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

PageTableEntry* PageTable::page_table_pointed_by(PageTableEntry& entry) const {
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
	wrcr3((uintptr_t)PMM::virt_to_phys(m_ptl4));
}

Optional<PageTable> PageTable::clone() const {
	uintptr_t ptl4_paddr = clone_page_table(4, m_ptl4);
	if (!ptl4_paddr)
		return {};
	PageTable copy(false);
	copy.set(ptl4_paddr);
	copy.map_kernel();
	return copy;
}

uintptr_t PageTable::clone_page_table(int level, PageTableEntry* table) const {
	uintptr_t frame = PMM::alloc_frame();
	if (!frame)
		return 0;

	PageTableEntry* copy = (PageTableEntry*)PMM::phys_to_virt(frame);

	for (size_t i = 0; i < PTRS_PER_PTL1; i++) {
		PageTableEntry& entry = table[i];
		if (!entry.is_present())
			continue;

		uintptr_t frame_base;
		if (entry.is_shared()) {
			frame_base = entry.frame_base();
		} else if (level > 1) {
			frame_base = clone_page_table(level-1, page_table_pointed_by(entry));
		} else {
			frame_base = PMM::dup_frame(entry.frame_base());
		}
		if (!frame_base)
			goto error;
		copy[i].set_frame_base(frame_base);
		copy[i].set_flags(entry.flags());
	}

	return frame;

	error:
	// TODO: cleanup
	return 0;
}

bool PageTable::operator==(const PageTable& other) const {
	return m_ptl4 == other.m_ptl4;
}
bool PageTable::operator!=(const PageTable& other) const {
	return !(*this == other);
}

KernelPageTable::KernelPageTable()
	: PageTable(false)
{
	// We can't set_current_cr3() here, because PMM is not initialized when the
	// global kernel page table is constructed.
}

void KernelPageTable::init() {
	set_current_cr3();
}

bool KernelPageTable::map(uintptr_t virt, uintptr_t phys, uint64_t page_flags,
                          bool discard_already_mapped)
{
	ASSERT(virt >= LAST_PTL4_ENTRY_ADDR, "addr below last ptl4: %p", virt);
	return PageTable::map(virt, phys, page_flags, discard_already_mapped);
}

bool KernelPageTable::unmap(uintptr_t virt, bool ignore_not_mapped) {
	ASSERT(virt >= LAST_PTL4_ENTRY_ADDR, "addr below last ptl4: %p", virt);
	return PageTable::unmap(virt, ignore_not_mapped);
}

PageTableEntry* KernelPageTable::ensure_pte(uintptr_t page_addr) {
	ASSERT(page_addr >= LAST_PTL4_ENTRY_ADDR, "addr below last ptl4: %p", page_addr);
	return PageTable::ensure_pte(page_addr);
}