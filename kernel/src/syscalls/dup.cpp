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

int Process::do_sys_dup2(int old_fd, int new_fd) {
	if (!m_open_files.count(old_fd))
		return -EBADF;
	if (old_fd == new_fd)
		return old_fd;

	// Close new_fd if it existed
	if (m_open_files.count(new_fd)) {
		FileDescription* description = m_open_files[new_fd];
		m_open_files.erase({new_fd, description});
		description->unref();
	}

	// Dup old_fd in new_fd
	FileDescription* desc = m_open_files[old_fd];
	m_open_files[new_fd] = desc;
	desc->ref();
	return new_fd;
}