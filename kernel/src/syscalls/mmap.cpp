#include "process.h"
#include "mem.h"
#include "linux/mman.h"

uint64_t prot_to_page_flags(int prot) {
	ASSERT(!(prot & PROT_GROWSDOWN) && !(prot & PROT_GROWSUP), "prot: %d", prot);
	uint64_t page_flags = PDE64_USER;
	if (prot == PROT_NONE)
		page_flags |= PDE64_PROTNONE;
	else {
		// There's no way of having writable but not readable pages
		if (prot & PROT_WRITE)
			page_flags |= PDE64_RW;
		if (!(prot & PROT_EXEC))
			page_flags |= PDE64_NX;
	}
	return page_flags;
}

uintptr_t Process::do_sys_mmap(UserPtr<void*> addr, size_t length, int prot,
                               int flags, int fd, size_t offset)
{
	dbgprintf("mmap(%p, %lu, 0x%x, 0x%x, %d, %p)\n", addr, length, prot,
	          flags, fd, offset);
	if (fd != -1 && !m_open_files.count(fd))
		return -EBADF;

	// We're not supporting multiple threads, so MAP_SHARED can be safely
	// removed
	if (flags & MAP_SHARED) {
		flags &= ~MAP_SHARED;
		//printf_once("REMOVING MAP SHARED\n");
	}

	int supported_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE | MAP_FIXED;
	ASSERT((flags & supported_flags) == flags, "unsupported flags 0x%x", flags);

	// Parse perms
	uint64_t page_flags = prot_to_page_flags(prot);
	if (!(prot & PROT_WRITE) && fd != -1)
		page_flags |= PDE64_RW; // read only file: map as writable first

	// Round length to upper page boundary and check if we have enough memory
	size_t length_upper = PAGE_CEIL(length);
	if (length_upper == 0 || !Mem::Virt::enough_free_memory(length_upper))
		return -ENOMEM;

	// Allocate memory
	void* ret;
	if (flags & MAP_FIXED) {
		if (addr.is_null() || ((addr.flat() & PTL1_MASK) != addr.flat()))
			return -EINVAL;
		ret = addr.ptr();
		Mem::Virt::alloc(ret, length_upper, page_flags);
	} else {
		ret = Mem::Virt::alloc(length_upper, page_flags);
	}

	// If a file descriptor was specified, copy its content to memory
	if (fd != -1) {
		const FileDescription& f = m_open_files[fd];
		// User seems to be allowed to map beyond the file limits (when
		// offset + length > f.size()). Let's see if offset > f.size() is
		// supposed to be allowed.
		ASSERT(offset <= f.size(), "offset OOB: %p / %p", offset, f.size());
		memcpy(ret, f.buf() + offset, min(f.size() - offset, length));

		// If it was read only, remove write permissions after copying content
		if (!(prot & PROT_WRITE)) {
			page_flags &= ~PDE64_RW;
			Mem::Virt::set_flags(ret, length_upper, page_flags);
		}
	}

	return (uintptr_t)ret;
}

int Process::do_sys_munmap(UserPtr<void*> addr, size_t length) {
	// Round length to upper page boundary
	length = PAGE_CEIL(length);
	if (!length || ((addr.flat() & PTL1_MASK) != addr.flat()))
		return -EINVAL;
	Mem::Virt::free(addr.ptr(), length);
	return 0;
}

int Process::do_sys_mprotect(UserPtr<void*> addr, size_t length, int prot) {
	uint64_t page_flags = prot_to_page_flags(prot);
	Mem::Virt::set_flags(addr.ptr(), length, page_flags);
	return 0;
}