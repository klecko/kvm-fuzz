#include "process.h"

ssize_t Process::do_sys_readlink(UserPtr<const char*> pathname_ptr,
                               UserPtr<char*> buf, size_t bufsize)
{
	string pathname;
	if (bufsize == 0)
		return -EINVAL;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;
	ASSERT(pathname == "/proc/self/exe", "not implemented %s", pathname.c_str());

	// TODO: size_t doesn't fit in ssize_t
	// Readlink does not append a null byte to buf
	size_t size = min(m_elf_path.size(), bufsize);
	return (copy_to_user(buf, m_elf_path.c_str(), size) ? size : -EFAULT);
}