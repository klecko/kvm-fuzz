#ifndef _MEM_PAGE_TABLE_H
#define _MEM_PAGE_TABLE_H

#include "libcpp/optional.h"
#include "x86/page_table.h"
#include "hypercalls.h"

class PageTable {
public:
	PageTable(bool create=true);
	// PageTable(uintptr_t ptl4_paddr);

	void set(uintptr_t ptl4_paddr);

	void set_current_cr3();

	void map_kernel();

	bool map(uintptr_t virt, uintptr_t phys, uint64_t page_flags,
	         bool discard_already_mapped = false);

	bool unmap(uintptr_t virt, bool ignore_not_mapped = false);

	PageTableEntry* ensure_pte(uintptr_t page_addr);

	void load();

	Optional<PageTable> clone() const;

	bool operator==(const PageTable& other) const;
	bool operator!=(const PageTable& other) const;

private:
	PageTableLevel4Entry* m_ptl4;

	PageTableEntry* page_table_pointed_by(PageTableEntry& entry) const;
	bool ensure_entry_present(PageTableEntry& entry);
	uintptr_t clone_page_table(int level, PageTableEntry* table) const;
};

// PageTable, but you can't operate on memory lower than LAST_PTL4_ENTRY_ADDR
class KernelPageTable : public PageTable {
	void map_kernel() = delete;
	void load() = delete;

public:
	KernelPageTable();

	void init();

	bool map(uintptr_t virt, uintptr_t phys, uint64_t page_flags,
	         bool discard_already_mapped = false);

	bool unmap(uintptr_t virt, bool ignore_not_mapped = false);

	PageTableEntry* ensure_pte(uintptr_t page_addr);
};

#endif