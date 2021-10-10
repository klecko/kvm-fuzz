#include "process.h"

ssize_t Process::do_sys_read(int fd, UserPtr<void*> buf, size_t count) {
	if (!m_files.count(fd))
		return -EBADF;
	return m_files[fd]->read(buf, count);
}

ssize_t Process::do_sys_pread64(int fd, UserPtr<void*> buf, size_t count,
                                off_t offset)
{
	ASSERT(offset >= 0, "negative offset on fd %d: %ld", fd, offset);
	if (!m_files.count(fd))
		return -EBADF;

	// Change offset, read and restore offset
	FileDescription& file = *m_files[fd];
	size_t original_offset = file.offset();
	file.set_offset(offset);
	ssize_t ret = file.read(buf, count);
	file.set_offset(original_offset);
	return ret;
}