#ifndef _FS_FILE_DESCRIPTION_H
#define _FS_FILE_DESCRIPTION_H

#include "common.h"
#include "libcpp/user_ptr.h"
#include "linux/fcntl.h"
#include "asm/stat.h"

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

typedef unsigned long inode_t;

class FileDescription {
public:
	// Used by stat. Fstat should use the corresponding method in File
	static int stat_regular(UserPtr<struct stat*> stat_ptr, size_t file_size,
					        inode_t inode);
	static int stat_stdin(UserPtr<struct stat*> stat_ptr);
	static int stat_stdout(UserPtr<struct stat*> stat_ptr);

	FileDescription(uint32_t flags, const char* buf, size_t size);
	virtual ~FileDescription() {};

	void ref();
	void unref();

	uint32_t flags() const;
	void set_flags(uint32_t flags);
	const char* buf() const;
	const char* cursor() const;
	bool is_readable() const;
	bool is_writable() const;
	size_t size() const;
	size_t offset() const;
	void set_offset(size_t offset);

	virtual bool is_socket() const { return false; }

	// File operations
	virtual int stat(UserPtr<struct stat*> stat_ptr) const;
	virtual ssize_t read(UserPtr<void*> buf, size_t len);
	virtual ssize_t write(UserPtr<const void*> buf, size_t len);

protected:
	// Set file buffer and size
	void set_buf(const char* buf, size_t size);

private:
	size_t m_ref_count;

	// Flags specified when calling open (O_RDONLY, O_RDWR...)
	uint32_t m_flags;

	// Pointer to file content
	const char* m_buf;

	// File size
	size_t m_size;

	// Cursor offset
	size_t m_offset;

	// Attempt to move the cursor. Returns the real increment performed,
	// emulating read or write
	size_t move_cursor(size_t increment);
};

class FileDescriptionStdin : public FileDescription {
public:
	FileDescriptionStdin();
	int stat(UserPtr<struct stat*> stat_ptr) const override;
	ssize_t read(UserPtr<void*> buf, size_t len) override;
	ssize_t write(UserPtr<const void*> buf, size_t len) override;

private:
	bool m_input_opened;
};

class FileDescriptionStdout : public FileDescription {
public:
	FileDescriptionStdout();
	int stat(UserPtr<struct stat*> stat_ptr) const override;
	ssize_t read(UserPtr<void*> buf, size_t len) override;
	ssize_t write(UserPtr<const void*> buf, size_t len) override;
};

typedef FileDescriptionStdout FileDescriptionStderr;


struct SocketType {
	int domain;
	int type;
	int protocol;
};

class FileDescriptionSocket : public FileDescription {
public:
	FileDescriptionSocket(const char* buf, size_t size, SocketType type);

	bool is_socket() const override { return true; }
	SocketType type() const;
	bool is_binded() const;
	void set_binded(bool);
	bool is_listening() const;
	void set_listening(bool);
	bool is_connected() const;
	void set_connected(bool);

	int stat(UserPtr<struct stat*> stat_ptr) const override;
	ssize_t read(UserPtr<void*> buf, size_t len) override;
	ssize_t write(UserPtr<const void*> buf, size_t len) override;
	int bind(UserPtr<const struct sockaddr*> addr_ptr, size_t addr_len);
	int listen(int backlog);

private:
	SocketType m_type;
	bool m_binded;
	bool m_listening;
	bool m_connected;
};

#endif