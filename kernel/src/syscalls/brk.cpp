#include "process.h"

uintptr_t Process::do_sys_brk(uintptr_t addr) {
	dbgprintf("trying to set brk to %p, current is %p\n", addr, m_brk);
	if (addr < m_min_brk)
		return m_brk;

	uintptr_t next_page = PAGE_CEIL(m_brk);
	uintptr_t cur_page  = m_brk & PTL1_MASK;
	if (addr > next_page) {
		// We have to allocate space. Check wrapping first
		size_t sz = PAGE_CEIL(addr - next_page);
		if (next_page + sz < next_page)
			return m_brk;
		Range range(next_page, sz);
		if (!m_space.map_range(range, MemPerms::Read | MemPerms::Write))
			return m_brk;

	} else if (addr <= cur_page) {
		// Free space
		uintptr_t addr_next_page = PAGE_CEIL(addr);
		m_space.unmap_range({addr_next_page, next_page - addr_next_page});
	}

	dbgprintf("brk set to %p\n", addr);
	m_brk = addr;
	return m_brk;
}