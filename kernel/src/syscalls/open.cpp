#include "process.h"
#include "fs/file_manager.h"
#include "linux/uio.h"

int Process::do_sys_openat(int dirfd, UserPtr<const char*> pathname_ptr,
                           int flags, mode_t mode)
{
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;

	ASSERT(dirfd == AT_FDCWD, "%s dirfd %d", pathname.c_str(), dirfd);
	dbgprintf("opening %s\n", pathname_ptr);

	// Find unused fd
	int fd = available_fd();

	// Let's open the file. Special hacky case for stdout.
	if (pathname == "stdout") {
		m_open_files[fd] = FileManager::open(FileManager::SpecialFile::Stdout);
		return fd;
	}

	// Every other file
	if (!FileManager::exists(pathname)) {
		dbgprintf("warning: opening unknown file '%s'\n", pathname.c_str());
		return -ENOENT;
	}
	ASSERT(!((flags & O_WRONLY) || (flags & O_RDWR)),
	       "%s with write permisions", pathname.c_str());
	m_open_files[fd] = FileManager::open(pathname, flags);
	return fd;
}

int Process::do_sys_open(UserPtr<const char*> pathname_ptr, int flags,
                        mode_t mode)
{
	return do_sys_openat(AT_FDCWD, pathname_ptr, flags, mode);
}

int Process::do_sys_close(int fd) {
	if (!m_open_files.count(fd))
		return -EBADF;
	FileDescription* description = m_open_files[fd];
	m_open_files.erase({fd, description});
	description->unref();
	return 0;
}