#ifndef _MEM_RANGE_H
#define _MEM_RANGE_H

#include "common.h"
#include "x86/page_table.h"

class Range {
	friend class AddressSpace;

public:
	Range(uintptr_t base, size_t size)
		: m_base(base)
		, m_size(size)
	{
		ASSERT((base & PTL1_MASK) == base, "not aligned base: %p", base);
		ASSERT((size & PTL1_MASK) == size, "not aligned size: %p", size);
		ASSERT(base + size >= base, "range wraps: %p %p", base, size);
		ASSERT(size != 0, "range empty size, base %p", base);
	}

	uintptr_t base() const {
		return m_base;
	}

	void set_base(uintptr_t base) {
		m_base = base;
	}

	size_t size() const {
		return m_size;
	}

	size_t length() const {
		return m_size;
	}

	void set_size(size_t size) {
		ASSERT(!is_allocated(), "modifying size of allocated range: %p", size);
		m_size = size;
	}

	bool is_allocated() const {
		return !m_frames.empty();
	}

private:
	uintptr_t m_base;
	size_t m_size;
	vector<uintptr_t> m_frames;
};

#endif