#include "process.h"
#include "linux/mman.h"

/* uint64_t prot_to_page_flags(int prot) {
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
 */
/* uintptr_t Process::do_sys_mmap(UserPtr<void*> addr, size_t length, int prot,
                               int flags, int fd, size_t offset)
{
	dbgprintf("mmap(%p, %lu, 0x%x, 0x%x, %d, %p)\n", addr, length, prot,
	          flags, fd, offset);
	if (fd != -1 && !m_files.count(fd))
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
		const FileDescription& f = m_files[fd];
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
} */

uint8_t prot_to_mem_perms(int prot) {
	uint8_t perms = MemPerms::None;
	if (prot & PROT_READ)
		perms |= MemPerms::Read;
	if (prot & PROT_WRITE)
		perms |= MemPerms::Write;
	if (prot & PROT_EXEC)
		perms |= MemPerms::Exec;
	return perms;
}

uintptr_t Process::do_sys_mmap(UserPtr<void*> addr, size_t length, int prot,
                               int flags, int fd, size_t offset)
{
	ASSERT(!(prot & PROT_GROWSDOWN) && !(prot & PROT_GROWSUP), "prot: %d", prot);
	dbgprintf("mmap(%p, %lu, 0x%x, 0x%x, %d, %p)\n", addr.flat(), length, prot,
	          flags, fd, offset);

	int supported_flags = MAP_PRIVATE | MAP_SHARED | MAP_ANONYMOUS |
	                      MAP_FIXED | MAP_DENYWRITE | MAP_STACK;
	ASSERT((flags & supported_flags) == flags, "unsupported flags 0x%x", flags);

	// Check given file descriptor is valid
	if (fd != -1 && !m_files.count(fd))
		return -EBADF;

	// We must return EINVAL if no length, and ENOMEM if length wraps
	if (!length)
		return -EINVAL;
	size_t length_upper = PAGE_CEIL(length);
	if (!length_upper)
		return -ENOMEM;

	bool map_private = flags & MAP_PRIVATE;
	bool map_shared = flags & MAP_SHARED;
	bool map_anonymous = flags & MAP_ANONYMOUS;
	bool map_fixed = flags & MAP_FIXED;

	// Shared and private: choose one
	if (map_shared && map_private)
		return -EINVAL;
	if (!map_shared && !map_private)
		return -EINVAL;

	// If MAP_FIXED, addr can't be null or not aligned
	if (map_fixed && (addr.is_null() || !IS_PAGE_ALIGNED(addr.flat())))
		return -EINVAL;

	// If it's a read only file, map it as writable first
	uint8_t perms = prot_to_mem_perms(prot);
	if (fd != -1)
		perms |= MemPerms::Write;

	// Note: when MAP_FIXED, a part of the specified range may already be mapped.
	uint8_t map_flags = 0;
	if (map_fixed)
		map_flags |= AddressSpace::MapFlags::DiscardAlreadyMapped;
	if (map_shared)
		map_flags |= AddressSpace::MapFlags::Shared;

	// Map range into our address space. If it fails, MAP_FIXED is not set and
	// the given address is not null, then ignore that address and try to map
	// it wherever we can. If that fails again, then it's ENOMEM.
	Range range(addr.flat() & PTL1_MASK, length_upper);
	bool success = m_space.map_range(range, perms, map_flags);
	if (!success && !map_fixed && !addr.is_null()) {
		range.set_base(0);
		success = m_space.map_range(range, perms, map_flags);
	}
	if (!success)
		return -ENOMEM;

	// Range is already mapped
	void* ret = (void*)range.base();

	// If a file descriptor was specified, copy its content to memory
	if (fd != -1) {
		const FileDescription& f = *m_files[fd];
		// User seems to be allowed to map beyond the file limits (when
		// offset + length > f.size()). Let's see if offset > f.size() is
		// supposed to be allowed.
		ASSERT(offset <= f.size(), "offset OOB: %p / %p", offset, f.size());
		memcpy(ret, f.buf() + offset, min(f.size() - offset, length));

		// If it was read only, remove write permissions after copying content
		if (!(prot & PROT_WRITE)) {
			perms &= ~MemPerms::Write;
			m_space.set_range_perms(range, perms);
		}
	}

	return (uintptr_t)ret;
}

int Process::do_sys_munmap(UserPtr<void*> addr, size_t length) {
	// Round length to upper page boundary
	length = PAGE_CEIL(length);
	if (!length || !IS_PAGE_ALIGNED(addr.flat()))
		return -EINVAL;

	Range range(addr.flat(), length);
	if (!m_space.unmap_range(range, true))
		return -EINVAL;
	return 0;
}

int Process::do_sys_mprotect(UserPtr<void*> addr, size_t length, int prot) {
	ASSERT(!(prot & PROT_GROWSDOWN) && !(prot & PROT_GROWSUP), "prot: %d", prot);
	if (!IS_PAGE_ALIGNED(addr.flat()))
		return -EINVAL;

	// Check if length wraps
	size_t length_upper = PAGE_CEIL(length);
	if (length_upper == 0 && length != 0)
		return -ENOMEM;

	Range range(addr.flat(), length_upper);
	if (!m_space.set_range_perms(range, prot_to_mem_perms(prot)))
		return -ENOMEM;
	return 0;
}