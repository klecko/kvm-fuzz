#include "process.h"
#include "fs/file_manager.h"
#include "asm/socket.h"

int Process::do_sys_socket(int domain, int type, int protocol) {
	int fd = available_fd();
	m_open_files[fd] = FileManager::open_socket({ domain, type, protocol });
	return fd;
}

int Process::do_sys_setsockopt(int sockfd, int level, int optname,
                               UserPtr<const void*> optval_ptr,
							   socklen_t optlen)
{
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;
	printf_once("TODO: setsockopt\n");
	return 0;
}

int Process::do_sys_bind(int sockfd, UserPtr<const struct sockaddr*> addr_ptr,
                         socklen_t addr_len)
{
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;
	auto socket = (FileDescriptionSocket*)m_open_files[sockfd];
	return socket->bind(addr_ptr, addr_len);
}

int Process::do_sys_listen(int sockfd, int backlog) {
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;
	auto socket = (FileDescriptionSocket*)m_open_files[sockfd];
	return socket->listen(backlog);
}

int Process::do_sys_accept(int sockfd, UserPtr<struct sockaddr*> addr_ptr,
                           UserPtr<socklen_t*> addr_len_ptr)
{
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;

	auto socket = (FileDescriptionSocket*)m_open_files[sockfd];
	if (!socket->is_binded() || !socket->is_listening()) // bind shouldn't be necessary
		return -EINVAL;
	auto accepted_socket = FileManager::open_socket(socket->type());
	accepted_socket->set_connected(true);

	// TODO: write into addr_ptr and addr_len_ptr

	int accepted_fd = available_fd();
	m_open_files[accepted_fd] = accepted_socket;
	return accepted_fd;
}

int Process::do_sys_getpeername(int sockfd, UserPtr<struct sockaddr*> addr_ptr,
                                UserPtr<socklen_t*> addr_len_ptr)
{
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;
	TODO
	return 0;
}

ssize_t Process::do_sys_recvfrom(
	int sockfd, UserPtr<void*> buf, size_t len,
    int flags, UserPtr<struct sockaddr*> src_addr_ptr,
	UserPtr<socklen_t*> addr_len_ptr
) {
	ASSERT(flags == 0, "TODO");
	ASSERT(src_addr_ptr.is_null(), "TODO");
	ASSERT(addr_len_ptr.is_null(), "TODO");
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;
	return m_open_files[sockfd]->read(buf, len);
}

ssize_t Process::do_sys_sendto(
	int sockfd, UserPtr<void*> buf, size_t len, int flags,
	UserPtr<const struct sockaddr*> dest_addr_ptr, socklen_t addr_len
) {
	ASSERT(flags == 0, "TODO");
	ASSERT(dest_addr_ptr.is_null(), "TODO");
	ASSERT(addr_len == 0, "TODO");
	if (!m_open_files.count(sockfd))
		return -EBADF;
	if (!m_open_files[sockfd]->is_socket())
		return -ENOTSOCK;

	// Don't do anything
	return len;
}

ssize_t Process::do_sys_sendfile(int out_fd, int in_fd, UserPtr<off_t*> off_ptr,
                                 ssize_t count)
{
	if (count < 0 || !m_open_files.count(out_fd) || !m_open_files.count(in_fd))
		return -EINVAL;
	FileDescription* out_file = m_open_files[out_fd];
	FileDescription* in_file = m_open_files[in_fd];
	if (!out_file->is_writable() || !in_file->is_readable())
		return -EBADF;

	// TODO: do this

	return count;
}