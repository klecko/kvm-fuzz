#include "fs/file_description.h"
#include "fs/file_manager.h"
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

FileDescription::FileDescription(uint32_t flags, const char* buf, size_t size)
	: m_ref_count(1)
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

void FileDescription::set_buf(const char* buf, size_t size) {
	m_buf = buf;
	m_size = size;
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


// REGULAR FILE
int FileDescription::stat(UserPtr<struct stat*> stat_ptr) const {
	return stat_regular(stat_ptr, m_size, (inode_t)m_buf);
}

ssize_t FileDescription::read(UserPtr<void*> buf, size_t len) {
	ASSERT(is_readable(), "trying to read from not readable file");

	// Get cursor, move it, and try to write to memory the resulting length
	const char* p = cursor();
	len = move_cursor(len);
	return (copy_to_user(buf, p, len) ? len : -EFAULT);
}

ssize_t FileDescription::write(UserPtr<const void*> buf, size_t len) {
	TODO
	return 0;
}


// STDIN
FileDescriptionStdin::FileDescriptionStdin()
	: FileDescription(0, nullptr, 0)
	, m_input_opened(false)
{
}

int FileDescriptionStdin::stat(UserPtr<struct stat*> stat_ptr) const {
	TODO
	return 0;
}

ssize_t FileDescriptionStdin::read(UserPtr<void*> buf, size_t len) {
	// Guest is trying to read from stdin. Let's do a little hack here.
	// Assuming it's expecting to read from input file, let's set that input
	// file as our buffer, and read from there as a regular file.
	// We can't do this at the beginning, as we wouldn't get the real size from
	// the hypervisor when it updated the input file.
	if (!m_input_opened) {
		m_input_opened = true;
		struct iovec input = FileManager::file_content("input");
		set_buf((const char*)input.iov_base, input.iov_len);
	}
	return FileDescription::read(buf, len);
}

ssize_t FileDescriptionStdin::write(UserPtr<const void*> buf, size_t len) {
	TODO
	return 0;
}


// STDOUT
FileDescriptionStdout::FileDescriptionStdout()
	: FileDescription(0, nullptr, 0)
{
}

int FileDescriptionStdout::stat(UserPtr<struct stat*> stat_ptr) const {
	return stat_stdout(stat_ptr);
}

ssize_t FileDescriptionStdout::read(UserPtr<void*> buf, size_t len) {
	TODO
	return 0;
}

ssize_t FileDescriptionStdout::write(UserPtr<const void*> buf, size_t len) {
	ssize_t ret = len;
#ifdef ENABLE_GUEST_OUTPUT
	ret = print_user(buf, len);
#endif
	return ret;
}


// SOCKET
FileDescriptionSocket::FileDescriptionSocket(const char* buf, size_t size,
                                             SocketType type)
	: FileDescription(O_RDWR, buf, size)
	, m_type(type)
	, m_binded(false)
	, m_listening(false)
	, m_connected(false)
{
}

SocketType FileDescriptionSocket::type() const {
	return m_type;
}

bool FileDescriptionSocket::is_binded() const {
	return m_binded;
}

void FileDescriptionSocket::set_binded(bool binded) {
	m_binded = binded;
}

bool FileDescriptionSocket::is_listening() const {
	return m_listening;
}

void FileDescriptionSocket::set_listening(bool listening) {
	m_listening = listening;
}

bool FileDescriptionSocket::is_connected() const {
	return m_connected;
}

void FileDescriptionSocket::set_connected(bool connected) {
	m_connected = connected;
}

int FileDescriptionSocket::stat(UserPtr<struct stat*> stat_ptr) const {
	TODO
	return 0;
}

ssize_t FileDescriptionSocket::read(UserPtr<void*> buf, size_t len) {
	if (!m_connected)
		return -ENOTCONN;
	return FileDescription::read(buf, len);
}

ssize_t FileDescriptionSocket::write(UserPtr<const void*> buf, size_t len) {
	TODO
	return 0;
}

int FileDescriptionSocket::bind(UserPtr<const struct sockaddr*> addr_ptr,
                                size_t addr_len)
{
	set_binded(true);
	return 0;
}

int FileDescriptionSocket::listen(int backlog) {
	// This is possible. In that case, the OS must assign the address and port.
	ASSERT(is_binded(), "listening on not binded socket");
	set_listening(true);
	return 0;
}