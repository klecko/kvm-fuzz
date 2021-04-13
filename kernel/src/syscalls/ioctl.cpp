#include "process.h"
#include "linux/termios.h"

int Process::do_sys_ioctl(int fd, uint64_t request, uint64_t arg) {
	if (!m_open_files.count(fd))
		return -EBADF;
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
		// We hold the whole struct termios2, but guest may want just a
		// struct termios
		bool success;
		if (request == TCGETS) {
			success = copy_to_user(UserPtr<struct termios*>(arg),
			                       (struct termios*)&m_term);
		} else if (request == TCGETS2) {
			success = copy_to_user(UserPtr<struct termios2*>(arg), &m_term);
		} else TODO;
		return (success ? 0 : -EFAULT);
	}
	ASSERT(false, "TODO ioctl, fd: %d, request: %p, arg: %p", fd, request, arg);
	return 0;
}