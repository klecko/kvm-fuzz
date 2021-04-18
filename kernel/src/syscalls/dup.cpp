#include "process.h"

int Process::do_sys_dup(int old_fd) {
	if (!m_open_files.count(old_fd))
		return -EBADF;
	FileDescription* description = m_open_files[old_fd];
	int new_fd = available_fd();
	m_open_files[new_fd] = description;
	description->ref();
	return new_fd;
}