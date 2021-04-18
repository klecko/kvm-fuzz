#ifndef _MEM_PAGE_TABLE_H
#define _MEM_PAGE_TABLE_H

#include "x86/page_table.h"
#include "hypercalls.h"

class PageTable {
public:
	PageTable();
	PageTable(uintptr_t ptl4_paddr);

	void set(uintptr_t ptl4_paddr);

	// TODO
	// void map_kernel(const PageTable& kernel_page_table);

	bool map(uintptr_t virt, uintptr_t phys, uint64_t page_flags,
	         bool discard_already_mapped = false);

	bool unmap(uintptr_t virt, bool ignore_not_mapped = false);

	PageTableEntry* ensure_pte(uintptr_t page_addr);

	void load();

private:
	PageTableLevel4Entry* m_ptl4;

	PageTableEntry* page_table_pointed_by(PageTableEntry& entry);
	bool ensure_entry_present(PageTableEntry& entry);

};

#endif