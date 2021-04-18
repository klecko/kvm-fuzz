#include "process.h"
#include "linux/fcntl.h"

int Process::do_sys_fcntl(int fd, int cmd, uint64_t arg) {
	if (!m_open_files.count(fd))
		return -EBADF;
	FileDescription& file = *m_open_files[fd];
	uint64_t ret = 0;
	uint32_t flags;
	switch (cmd) {
		// There's only one flag defined for F_GETFD and F_SETFD: FD_CLOEXEC.
		// It can also be specified when opening, with O_CLOEXEC.
		// For simplicity, save it as O_CLOEXEC
		case F_GETFD:
			ret = (file.flags() & O_CLOEXEC ? FD_CLOEXEC : 0);
			break;
		case F_SETFD:
			flags = file.flags();
			if (arg & FD_CLOEXEC)
				flags |= O_CLOEXEC;
			file.set_flags(flags);
			ret = 0;
			break;
		default:
			ASSERT(false, "TODO cmd = %d", cmd);
	}
	return ret;
}