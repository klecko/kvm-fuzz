#include "address_space.h"
#include "pmm.h"
#include "x86/page_table.h"
#include "x86/asm.h"

AddressSpace::AddressSpace(uintptr_t ptl4_paddr)
	: m_page_table(ptl4_paddr)
{
}

bool AddressSpace::alloc_range(Range& range) {
	// Try to allocate physical memory
	vector<uintptr_t> frames;
	size_t num_frames = PAGE_CEIL(range.size()) / PAGE_SIZE;
	if (!PMM::alloc_frames(num_frames, frames))
		return false;

	range.m_frames = move(frames);
	return true;
}

bool AddressSpace::free_range(Range& range) {
	if (!range.is_allocated())
		return false;

	for (uintptr_t frame : range.m_frames)
		PMM::free_frame(frame);
	range.m_frames.clear();
	return true;
}

bool AddressSpace::map_range(Range& range, uint8_t perms,
                             bool discard_already_mapped)
{
	if (perms == MemPerms::None) TODO
	ASSERT(range.is_allocated(), "not allocated range: %p %p",
	       range.base(), range.size());
	size_t num_frames = PAGE_CEIL(range.size()) / PAGE_SIZE;
	size_t real_num_frames = range.m_frames.size();
	ASSERT(real_num_frames == num_frames, "number of frames doesnt match,"
	       " should be %lu but it's %lu", num_frames, real_num_frames);

	if (!range.base()) {
		range.set_base(m_next_user_mapping);
		m_next_user_mapping += range.size();
	}

	for (size_t i = 0; i < num_frames; i++) {
		uintptr_t page_base = range.base() + i*PAGE_SIZE;
		uint64_t page_flags = PageTableEntry::User;
		if (perms & MemPerms::Write)
			page_flags |= PageTableEntry::ReadWrite;
		if (!(perms & MemPerms::Exec))
			page_flags |= PageTableEntry::NoExecute;
		if (!m_page_table.map(page_base, range.m_frames[i], page_flags,
		                      discard_already_mapped))
			return false;
	}
	return true;
}

bool AddressSpace::unmap_range(const Range& range, bool ignore_not_mapped) {
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
		pte->set_writable(perms & MemPerms::Write);
		pte->set_execute_disabled(!(perms & MemPerms::Exec));
		flush_tlb_entry(page_base);
	}
	return true;
}