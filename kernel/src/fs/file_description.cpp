#include "fs/file_description.h"
#include "libcpp/libcpp.h"

int FileDescription::stat_regular(UserPtr<struct stat*> stat_ptr, size_t file_size,
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
		.st_atime        = 1615575193,
		.st_atime_nsec   = 228169446,
		.st_mtime        = 1596888770,
		.st_mtime_nsec   = 0,
		.st_ctime        = 1612697533,
		.st_ctime_nsec   = 117084367,
	};
	struct stat st = regular_st;
	st.st_ino = inode;
	st.st_size = file_size;
	st.st_blocks = (file_size / 512) + 1;
	return (copy_to_user(stat_ptr, &st) ? 0 : -EFAULT);
}

int FileDescription::stat_stdout(UserPtr<struct stat*> stat_ptr) {
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
		.st_atime        = 0,
		.st_atime_nsec   = 0,
		.st_mtime        = 0,
		.st_mtime_nsec   = 0,
		.st_ctime        = 0,
		.st_ctime_nsec   = 0,
	};
	return (copy_to_user(stat_ptr, &stdout_st) ? 0 : -EFAULT);
}

const FileDescription::file_ops FileDescription::fops_regular = {
	.do_stat  = &FileDescription::do_stat_regular,
	.do_read  = &FileDescription::do_read_regular,
	.do_write = nullptr,
};

const FileDescription::file_ops FileDescription::fops_stdin = {
	.do_stat  = nullptr,
	.do_read  = nullptr,
	.do_write = nullptr,
};

const FileDescription::file_ops FileDescription::fops_stdout = {
	.do_stat  = &FileDescription::do_stat_stdout,
	.do_read  = nullptr,
	.do_write = &FileDescription::do_write_stdout,
};

const FileDescription::file_ops FileDescription::fops_stderr =
	FileDescription::fops_stdout;

FileDescription::FileDescription(uint32_t flags, const char* buf, size_t size)
	: m_fops(fops_regular)
	, m_ref_count(1)
	, m_flags(flags)
	, m_buf(buf)
	, m_size(size)
	, m_offset(0)
{ }

void FileDescription::ref() {
	m_ref_count++;
}

void FileDescription::unref() {
	ASSERT(m_ref_count != 0, "unref with ref_count = 0");
	m_ref_count--;
	if (m_ref_count == 0)
		delete this;
}

uint32_t FileDescription::flags() const {
	return m_flags;
}

void FileDescription::set_flags(uint32_t flags) {
	m_flags = flags;
}

bool FileDescription::is_readable() const {
	uint32_t accmode = m_flags & O_ACCMODE;
	return (accmode == O_RDONLY || accmode == O_RDWR);
}

bool FileDescription::is_writable() const {
	uint32_t accmode = m_flags & O_ACCMODE;
	return (accmode == O_WRONLY || accmode == O_RDWR);
}

const char* FileDescription::buf() const {
	return m_buf;
}

const char* FileDescription::cursor() const {
	return m_buf + m_offset;
}

size_t FileDescription::size() const {
	return m_size;
}

size_t FileDescription::offset() const {
	return m_offset;
}

void FileDescription::set_offset(size_t offset) {
	m_offset = offset;
}

size_t FileDescription::move_cursor(size_t increment) {
	// Check if offset is currently past end
	if (m_offset >= m_size)
		return 0;

	// Reduce increment if there is not enough space available
	size_t ret = (m_offset+increment < m_size ? increment : m_size-m_offset);

	// Update offset
	m_offset += ret;
	return ret;
}

int FileDescription::stat(UserPtr<struct stat*> stat_ptr) const {
	ASSERT(m_fops.do_stat, "not implemented stat");
	return (this->*m_fops.do_stat)(stat_ptr);
}

ssize_t FileDescription::read(UserPtr<void*> buf, size_t len) {
	ASSERT(m_fops.do_read, "not implemented read");
	return (this->*m_fops.do_read)(buf, len);
}

ssize_t FileDescription::write(UserPtr<const void*> buf, size_t len) {
	ASSERT(m_fops.do_write, "not implemented write");
	return (this->*m_fops.do_write)(buf, len);
}

// All fstat syscalls fall back to stat
int FileDescription::do_stat_regular(UserPtr<struct stat*> stat_ptr) const {
	return stat_regular(stat_ptr, m_size, (inode_t)m_buf);
}

int FileDescription::do_stat_stdout(UserPtr<struct stat*> stat_ptr) const {
	return stat_stdout(stat_ptr);
}

ssize_t FileDescription::do_read_regular(UserPtr<void*> buf, size_t len) {
	ASSERT(is_readable(), "trying to read from not readable file");

	// Get cursor, move it, and try to write to memory the resulting length
	const char* p = cursor();
	len = move_cursor(len);
	return (copy_to_user(buf, p, len) ? len : -EFAULT);
}

ssize_t FileDescription::do_write_stdout(UserPtr<const void*> buf, size_t len) {
	ssize_t ret = len;
#ifdef ENABLE_GUEST_OUTPUT
	ret = print_user(buf, len);
#endif
	return ret;
}


FileDescriptionStdin::FileDescriptionStdin()
	: FileDescription(O_RDONLY)
{
	m_fops = fops_stdin;
};

FileDescriptionStdout::FileDescriptionStdout()
	: FileDescription(O_WRONLY)
{
	m_fops = fops_stdout;
};

FileDescriptionStderr::FileDescriptionStderr()
	: FileDescription(O_WRONLY)
{
	m_fops = fops_stderr;
};