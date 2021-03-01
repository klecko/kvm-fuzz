#include <sys/fcntl.h>
#include "file.h"
#include "libcpp.h"

void stat_regular(void* statbuf, size_t filesize) {
	struct stat st;
	st.st_dev          = 2052;
	st.st_ino          = 11349843;
	st.st_mode         = 0100664;
	st.st_nlink        = 1;
	st.st_uid          = 0;
	st.st_gid          = 0;
	st.st_rdev         = 0;
	st.st_size         = filesize;
	st.st_atim.tv_sec  = 0;
	st.st_atim.tv_nsec = 0;
	st.st_mtim.tv_sec  = 0;
	st.st_mtim.tv_nsec = 0;
	st.st_ctim.tv_sec  = 0;
	st.st_ctim.tv_nsec = 0;
	st.st_blksize      = 4096;
	st.st_blocks       = (filesize/512) + 1;
	memcpy(statbuf, &st, sizeof(st));
}

void stat_stdout(void* statbuf) {
	struct stat st;
	st.st_dev          = 22;
	st.st_ino          = 6;
	st.st_mode         = 020620;
	st.st_nlink        = 1;
	st.st_uid          = 0;
	st.st_gid          = 0;
	st.st_rdev         = 34819;
	st.st_size         = 0;
	st.st_atim.tv_sec  = 0;
	st.st_atim.tv_nsec = 0;
	st.st_mtim.tv_sec  = 0;
	st.st_mtim.tv_nsec = 0;
	st.st_ctim.tv_sec  = 0;
	st.st_ctim.tv_nsec = 0;
	st.st_blksize      = 1024;
	st.st_blocks       = 0;
	memcpy(statbuf, &st, sizeof(st));
}

const file_ops File::fops_regular = {
	.do_stat  = &File::do_stat_regular,
	.do_read  = &File::do_read_regular,
	.do_write = NULL,
};

const file_ops File::fops_stdin = {
	.do_stat  = NULL,
	.do_read  = NULL,
	.do_write = NULL,
};

const file_ops File::fops_stdout = {
	.do_stat  = &File::do_stat_stdout,
	.do_read  = NULL,
	.do_write = &File::do_write_stdout,
};

const file_ops File::fops_stderr = File::fops_stdout;

File::File(uint32_t flags, const char* buf, size_t size)
	: m_fops(fops_regular)
	, m_flags(flags)
	, m_buf(buf)
	, m_size(size)
	, m_offset(0)
{ }

uint32_t File::flags() {
	return m_flags;
}

void File::set_flags(uint32_t flags) {
	m_flags = flags;
}

bool File::is_readable() {
	uint32_t accmode = m_flags & O_ACCMODE;
	return (accmode == O_RDONLY || accmode == O_RDWR);
}

bool File::is_writable() {
	uint32_t accmode = m_flags & O_ACCMODE;
	return (accmode == O_WRONLY || accmode == O_RDWR);
}

const char* File::cursor() {
	return m_buf + m_offset;
}

size_t File::size() {
	return m_size;
}

size_t File::offset() {
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

void File::stat(void* statbuf) {
	ASSERT(m_fops.do_stat, "not implemented stat");
	(this->*m_fops.do_stat)(statbuf);
}

size_t File::read(void* buf, size_t len) {
	ASSERT(m_fops.do_read, "not implemented read");
	return (this->*m_fops.do_read)(buf, len);
}

size_t File::write(const void* buf, size_t len) {
	ASSERT(m_fops.do_write, "not implemented write");
	return (this->*m_fops.do_write)(buf, len);
}

// All fstat syscalls fall back to stat
void File::do_stat_regular(void* statbuf) {
	stat_regular(statbuf, m_size);
}

void File::do_stat_stdout(void* statbuf) {
	stat_stdout(statbuf);
}

size_t File::do_read_regular(void* buf, size_t len) {
	ASSERT(is_readable(), "trying to read from not readable file");

	// Get cursor, move it, and write to memory the resulting length
	const char* p = cursor();
	len = move_cursor(len);
	memcpy(buf, p, len);
	return len;
}

size_t File::do_write_stdout(const void* buf, size_t len) {
#ifdef DEBUG
		/* char buf[len + 1];
		mmu.read_mem(buf, buf, len);
		buf[len] = 0;
		printf("%s", buf); */
#endif
	return len;
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