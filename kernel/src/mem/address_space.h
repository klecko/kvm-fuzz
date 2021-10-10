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
	static bool is_user_address(uintptr_t addr);
	static bool is_user_range(uintptr_t addr, size_t len);
	static bool is_user_range(const Range& range);

	AddressSpace(bool create=true);
	// AddressSpace(uintptr_t ptl4_paddr);

	enum MapFlags {
		DiscardAlreadyMapped = 1,
		Shared = (1 << 1),
	};

	// Allocate physical memory for given range and map it with given perms.
	// Also sets range base address to the address it was mapped to if it had
	// no base address.
	bool map_range(Range& range, uint8_t perms, uint8_t flags = 0);

	// Unmap a range from memory, and also free its memory
	// TODO: unmapping won't imply freeing when MAP_SHARED
	bool unmap_range(const Range& range, bool ignore_not_mapped = false);

	// Set perms to an already mapped range
	bool set_range_perms(const Range& range, uint8_t perms);

	Optional<AddressSpace> clone() const;

	void load();

	bool operator==(const AddressSpace& other) const;
	bool operator!=(const AddressSpace& other) const;

private:
	static const uintptr_t USER_MAPPINGS_START_ADDR = 0x7FFFF7FFE000;

	PageTable m_page_table;
	// vector<Range> m_free_ranges;
	// vector<Range> m_allocated_ranges;

	uintptr_t find_free_memory_region_for_range(const Range& range);

	void map_kernel();
};

#endif