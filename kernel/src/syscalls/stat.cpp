#include "process.h"
#include "fs/file_manager.h"

int Process::do_sys_stat(UserPtr<const char*> pathname_ptr,
                         UserPtr<struct stat*> stat_ptr)
{
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;

	if (!FileManager::exists(pathname)) {
		dbgprintf("warning: stat on unknown file '%s'\n", pathname.c_str());
		return -ENOENT;
	}
	return FileManager::stat(pathname, stat_ptr);
}

int Process::do_sys_fstat(int fd, UserPtr<struct stat*> stat_ptr) {
	if (!m_open_files.count(fd))
		return -EBADF;
	return m_open_files[fd]->stat(stat_ptr);
}