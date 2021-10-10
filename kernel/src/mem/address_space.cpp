#include "address_space.h"
#include "pmm.h"
#include "vmm.h"
#include "x86/page_table.h"
#include "x86/asm.h"

bool AddressSpace::is_user_address(uintptr_t addr) {
	return addr < 0x800000000000;
}

bool AddressSpace::is_user_range(uintptr_t addr, size_t len) {
	if (addr + len < addr)
		return false;
	return is_user_address(addr) && is_user_address(addr + len - 1);
}

bool AddressSpace::is_user_range(const Range& range) {
	return is_user_range(range.base(), range.size());
}

AddressSpace::AddressSpace(bool create)
	: m_page_table(create)
{
	if (!create)
		m_page_table.set_current_cr3();
}

// AddressSpace::AddressSpace(uintptr_t ptl4_paddr)
// 	: m_page_table(ptl4_paddr)
// {
// }

uintptr_t AddressSpace::find_free_memory_region_for_range(const Range& range) {
	ASSERT(range.base() == 0, "range already has base address");
	uintptr_t base = USER_MAPPINGS_START_ADDR;
	while (is_user_address(base)) {
		uintptr_t length;
		for (length = 0; length < range.length(); length += PAGE_SIZE) {
			PageTableEntry* pte = m_page_table.ensure_pte(base + length);
			if (!pte)
				return 0;
			if (pte->is_present())
				break;
		}

		// If the loop got to the end, we found our desired region
		if (length == range.length())
			return base;

		base += length + PAGE_SIZE;
	}
	return 0;
}

bool AddressSpace::map_range(Range& range, uint8_t perms, uint8_t flags) {
	// Assign a base address to the range in case it doesn't have one
	if (!range.base()) {
		uintptr_t base = find_free_memory_region_for_range(range);
		if (!base) {
			return false;
		}
		range.set_base(base);
	}

	// Check the range is in user range
	if (!is_user_range(range)) {
		return false;
	}

	// Attempt to allocate physical memory for the range
	vector<uintptr_t> frames;
	size_t num_frames = PAGE_CEIL(range.size()) / PAGE_SIZE;
	if (!PMM::alloc_frames(num_frames, frames)) {
		return false;
	}

	// Compute page flags according to memory permissions and mapping flags
	uint64_t page_flags = PageTableEntry::User;
	if (perms == MemPerms::None) {
		// ProtNone (which is the same as Global) without Present
		page_flags |= PageTableEntry::ProtNone;
	} else {
		page_flags |= PageTableEntry::Present;
		if (perms & MemPerms::Write)
			page_flags |= PageTableEntry::ReadWrite;
		if (!(perms & MemPerms::Exec))
			page_flags |= PageTableEntry::NoExecute;
	}
	if (flags & MapFlags::Shared)
		page_flags |= PageTableEntry::Shared;
	bool discard = flags & MapFlags::DiscardAlreadyMapped;

	// Map every page
	for (size_t i = 0; i < frames.size(); i++) {
		uintptr_t page_base = range.base() + i*PAGE_SIZE;
		if (!m_page_table.map(page_base, frames[i], page_flags, discard)) {
			return false;
		}
	}
	return true;
}

bool AddressSpace::unmap_range(const Range& range, bool ignore_not_mapped) {
	// Check the range is in user range
	if (!is_user_range(range))
		return false;

	// Unmap every page
	for (uintptr_t page_base = range.base();
	     page_base < range.base() + range.size();
	     page_base += PAGE_SIZE)
	{
		if (!m_page_table.unmap(page_base, ignore_not_mapped))
			return false;
	}
	return true;
}

bool AddressSpace::set_range_perms(const Range& range, uint8_t perms) {
	// Check the range is in user range
	if (!is_user_range(range))
		return false;

	// Set permissions to every page
	PageTableEntry* pte;
	for (uintptr_t page_base = range.base();
	     page_base < range.base() + range.size();
	     page_base += PAGE_SIZE)
	{
		pte = m_page_table.ensure_pte(page_base);
		if (!pte) {
			return false;
		}
		if (!pte->is_present()) {
			return false;
		}
		pte->set_prot_none(perms == MemPerms::None);
		pte->set_writable(perms & MemPerms::Write);
		pte->set_execute_disabled(!(perms & MemPerms::Exec));
		flush_tlb_entry(page_base);
	}
	return true;
}

Optional<AddressSpace> AddressSpace::clone() const {
	auto page_table_copy = m_page_table.clone();
	if (!page_table_copy.has_value())
		return false;

	AddressSpace copy(false);
	copy.m_page_table = page_table_copy.value();
	return copy;
}

void AddressSpace::load() {
	m_page_table.load();
}

bool AddressSpace::operator==(const AddressSpace& other) const {
	return m_page_table == other.m_page_table;
}

bool AddressSpace::operator!=(const AddressSpace& other) const {
	return !(*this == other);
}