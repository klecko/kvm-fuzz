#ifndef _PAGE_WALKER_H
#define _PAGE_WALKER_H

#include "common.h"
#include "mem.h"

class PageWalker {
public:
	PageWalker(void* start, size_t len);

	size_t offset() const;

	bool is_allocated() const;

	bool alloc_frame(uint64_t flags, bool assert_not_oom = true);

	void free_frame();

	void set_flags(uint64_t flags);

	bool next();

private:
	uintptr_t m_start;
	size_t m_len;
	size_t m_offset;
	uintptr_t* m_ptl4;
	uintptr_t* m_ptl3;
	uintptr_t* m_ptl2;
	uintptr_t* m_ptl1;
	uint64_t   m_ptl4_i;
	uint64_t   m_ptl3_i;
	uint64_t   m_ptl2_i;
	uint64_t   m_ptl1_i;
	bool m_oom;

	uintptr_t addr() const;
	uintptr_t& pte() const;

	void update_ptl3();
	void update_ptl2();
	void update_ptl1();
	void next_ptl4_entry();
	void next_ptl3_entry();
	void next_ptl2_entry();
	void next_ptl1_entry();
};

#endif