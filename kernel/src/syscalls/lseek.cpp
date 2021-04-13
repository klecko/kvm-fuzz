#include "process.h"
#include "linux/fs.h"

off_t Process::do_sys_lseek(int fd, off_t offset, int whence) {
	// We use signed types here, as the syscall does, but we use unsigned types
	// in File. The syscall fails if the resulting offset is negative, so
	// there isn't any problem about that
	if (!m_open_files.count(fd))
		return -EBADF;
	FileDescription& file = m_open_files[fd];
	off_t ret;
	switch (whence) {
		case SEEK_SET:
			ret = offset;
			break;

		case SEEK_CUR:
			ret = file.offset() + offset;
			break;

		case SEEK_END:
			ret = file.size() + offset;
			break;

		default:
			TODO
	}
	if (ret < 0)
		return -EINVAL;
	file.set_offset(ret);
	return ret;
}