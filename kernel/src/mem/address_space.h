#ifndef _MEM_ADDRESS_SPACE_H
#define _MEM_ADDRESS_SPACE_H

#include "vector"
#include "common.h"
#include "range.h"
#include "page_table.h"

enum MemPerms : uint8_t {
	None = 0,
	Read = (1 << 1),
	Write = (1 << 2),
	Exec = (1 << 3),
};

class AddressSpace {
public:
	AddressSpace(uintptr_t ptl4_paddr);

	// Given a range, attempt to allocate physical memory for it
	bool alloc_range(Range& range);

	// Free the physical memory allocated for given range, which must have been
	// allocated with `alloc_range`
	bool free_range(Range& range);

	// Map an allocated range into memory with given perms. Also sets range base
	// address to the address it was mapped to if it had no base address.
	bool map_range(Range& range, uint8_t perms,
	               bool discard_already_mapped = false);

	// Unmap a range from memory, and also free its memory
	// TODO: unmapping won't imply freeing when MAP_SHARED
	bool unmap_range(const Range& range, bool ignore_not_mapped = false);

	// Set perms to an already mapped range
	bool set_range_perms(const Range& range, uint8_t perms);

private:
	static const uintptr_t USER_MAPPINGS_START_ADDR = 0x7FFFF7FFE000;

	PageTable m_page_table;
	uintptr_t m_next_user_mapping;
	// vector<Range> m_free_ranges;
	// vector<Range> m_allocated_ranges;

};

#endif