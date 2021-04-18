#include "process.h"

ssize_t Process::do_sys_writev(int fd, UserPtr<const struct iovec*> iov_ptr,
                               int iovcnt)
{
	ASSERT(iovcnt >= 0, "negative iovcnt: %d", iovcnt);
	if (!m_open_files.count(fd))
		return -EBADF;

	ssize_t ret  = 0;
	FileDescription& file = *m_open_files[fd];

	// Write each iovec to file
	hc_print("WRITEV\n");
	struct iovec iov;
	for (int i = 0; i < iovcnt; i++) {
		// Copy iovec
		if (!copy_from_user(&iov, iov_ptr + i))
			return -EFAULT;

		// Perform write
		ssize_t n = file.write(UserPtr<const void*>(iov.iov_base), iov.iov_len);
		// ssize_t n = print_user(UserPtr<const void*>(iov.iov_base), iov.iov_len);
		if (n < 0)
			return n;
		ret += n;
	}

	//hc_print_stacktrace(m_user_regs->rsp, m_user_regs->rip, m_user_regs->rbp);
	// FaultInfo fault = {
	// 	.type = FaultInfo::Type::AssertionFailed,
	// 	.rip = m_user_regs->rip,
	// };
	// hc_fault(&fault);
	return ret;
}

ssize_t Process::do_sys_write(int fd, UserPtr<const void*> buf, size_t count) {
	if (!m_open_files.count(fd))
		return -EBADF;
	return m_open_files[fd]->write(buf, count);
}
