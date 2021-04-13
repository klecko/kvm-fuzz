#include "process.h"
#include "mem.h"

uintptr_t Process::do_sys_brk(uintptr_t addr) {
	dbgprintf("trying to set brk to %p, current is %p\n", addr, m_brk);
	if (addr < m_min_brk)
		return m_brk;

	uintptr_t next_page = PAGE_CEIL(m_brk);
	uintptr_t cur_page  = m_brk & PTL1_MASK;
	if (addr > next_page) {
		// We have to allocate space. Don't even bother to check if range is
		// free if there isn't enough free memory, but ensure there is after
		// checking it, because is_range_free consumes memory creating
		// page table directories. TODO: improve this shit
		size_t sz = PAGE_CEIL(addr - next_page);
		uint64_t flags = PDE64_USER | PDE64_RW;

		if (!Mem::Virt::enough_free_memory(sz)) {
			return m_brk;
		}

		if (!Mem::Virt::is_range_free((void*)next_page, sz)) {
			//printf_once("WARNING: brk range OOB allocating %lu\n", sz);
			return m_brk;
		}

		if (!Mem::Virt::enough_free_memory(sz)) {
			return m_brk;
		}

		Mem::Virt::alloc((void*)next_page, sz, flags);

	} else if (addr <= cur_page) {
		// Free space
		uintptr_t addr_next_page = PAGE_CEIL(addr);
		Mem::Virt::free((void*)addr_next_page, next_page - addr_next_page);
	}

	dbgprintf("brk set to %p\n", addr);
	m_brk = addr;
	return m_brk;
}