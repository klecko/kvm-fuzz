#include "file.h"
#include "libcpp.h"
#include <sys/fcntl.h>

int File::stat_regular(UserPtr<struct stat*> stat_ptr, size_t file_size,
                       inode_t inode)
{
	static constexpr struct stat regular_st = {
		.st_dev          = 2052,
		.st_ino          = 0,
		.st_nlink        = 1,
		.st_mode         = 0100664,
		.st_uid          = 0,
		.st_gid          = 0,
		.st_rdev         = 0,
		.st_size         = 0,
		.st_blksize      = 4096,
		.st_blocks       = 0,
		.st_atim         = {1615575193, 228169446},
		.st_mtim         = {1596888770, 0},
		.st_ctim         = {1612697533, 117084367}
	};
	struct stat st = regular_st;
	st.st_ino = inode;
	st.st_size = file_size;
	st.st_blocks = (file_size / 512) + 1;
	return (copy_to_user(stat_ptr, &st) ? 0 : -EFAULT);
}

int File::stat_stdout(UserPtr<struct stat*> stat_ptr) {
	static constexpr struct stat stdout_st = {
		.st_dev          = 22,
		.st_ino          = 6,
		.st_nlink        = 1,
		.st_mode         = 020620,
		.st_uid          = 0,
		.st_gid          = 0,
		.st_rdev         = 34819,
		.st_size         = 0,
		.st_blksize      = 1024,
		.st_blocks       = 0,
		.st_atim         = {0, 0},
		.st_mtim         = {0, 0},
		.st_ctim         = {0, 0}
	};
	return (copy_to_user(stat_ptr, &stdout_st) ? 0 : -EFAULT);
}

const File::file_ops File::fops_regular = {
	.do_stat  = &File::do_stat_regular,
	.do_read  = &File::do_read_regular,
	.do_write = NULL,
};

const File::file_ops File::fops_stdin = {
	.do_stat  = NULL,
	.do_read  = NULL,
	.do_write = NULL,
};

const File::file_ops File::fops_stdout = {
	.do_stat  = &File::do_stat_stdout,
	.do_read  = NULL,
	.do_write = &File::do_write_stdout,
};

const File::file_ops File::fops_stderr = File::fops_stdout;

File::File(uint32_t flags, const char* buf, size_t size)
	: m_fops(fops_regular)
	, m_flags(flags)
	, m_buf(buf)
	, m_size(size)
	, m_offset(0)
{ }

uint32_t File::flags() const {
	return m_flags;
}

void File::set_flags(uint32_t flags) {
	m_flags = flags;
}

bool File::is_readable() const {
	uint32_t accmode = m_flags & O_ACCMODE;
	return (accmode == O_RDONLY || accmode == O_RDWR);
}

bool File::is_writable() const {
	uint32_t accmode = m_flags & O_ACCMODE;
	return (accmode == O_WRONLY || accmode == O_RDWR);
}

const char* File::buf() const {
	return m_buf;
}

const char* File::cursor() const {
	return m_buf + m_offset;
}

size_t File::size() const {
	return m_size;
}

size_t File::offset() const {
	return m_offset;
}

void File::set_offset(size_t offset) {
	m_offset = offset;
}

size_t File::move_cursor(size_t increment) {
	// Check if offset is currently past end
	if (m_offset >= m_size)
		return 0;

	// Reduce increment if there is not enough space available
	size_t ret = (m_offset+increment < m_size ? increment : m_size-m_offset);

	// Update offset
	m_offset += ret;
	return ret;
}

int File::stat(UserPtr<struct stat*> stat_ptr) const {
	ASSERT(m_fops.do_stat, "not implemented stat");
	return (this->*m_fops.do_stat)(stat_ptr);
}

ssize_t File::read(UserPtr<void*> buf, size_t len) {
	ASSERT(m_fops.do_read, "not implemented read");
	return (this->*m_fops.do_read)(buf, len);
}

ssize_t File::write(UserPtr<const void*> buf, size_t len) {
	ASSERT(m_fops.do_write, "not implemented write");
	return (this->*m_fops.do_write)(buf, len);
}

// All fstat syscalls fall back to stat
int File::do_stat_regular(UserPtr<struct stat*> stat_ptr) const {
	return stat_regular(stat_ptr, m_size, (inode_t)m_buf);
}

int File::do_stat_stdout(UserPtr<struct stat*> stat_ptr) const {
	return stat_stdout(stat_ptr);
}

ssize_t File::do_read_regular(UserPtr<void*> buf, size_t len) {
	ASSERT(is_readable(), "trying to read from not readable file");

	// Get cursor, move it, and try to write to memory the resulting length
	const char* p = cursor();
	len = move_cursor(len);
	return (copy_to_user(buf, p, len) ? len : -EFAULT);
}

ssize_t File::do_write_stdout(UserPtr<const void*> buf, size_t len) {
	ssize_t ret = len;
#ifdef ENABLE_GUEST_OUTPUT
	ret = print_user(buf, len);
#endif
	return ret;
}


FileStdin::FileStdin()
	: File(O_RDONLY)
{
	m_fops = fops_stdin;
};

FileStdout::FileStdout()
	: File(O_WRONLY)
{
	m_fops = fops_stdout;
};

FileStderr::FileStderr()
	: File(O_WRONLY)
{
	m_fops = fops_stderr;
};