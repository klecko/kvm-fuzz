#ifndef _FILE_H
#define _FILE_H

#include <sys/stat.h>
#include "common.h"
#include "user_ptr.h"

typedef unsigned long inode_t;

class File {
public:
	// Used by stat. Fstat should use the corresponding method in File
	static int stat_regular(UserPtr<struct stat*> stat_ptr, size_t file_size,
					        inode_t inode);
	static int stat_stdout(UserPtr<struct stat*> stat_ptr);

	File(uint32_t flags = 0, const char* buf = NULL, size_t size = 0);

	uint32_t flags() const;
	void set_flags(uint32_t flags);
	const char* buf() const;
	const char* cursor() const;
	bool is_readable() const;
	bool is_writable() const;
	size_t size() const;
	size_t offset() const;
	void set_offset(size_t offset);

	// File operations
	int stat(UserPtr<struct stat*> stat_ptr) const;
	ssize_t read(UserPtr<void*> buf, size_t len);
	ssize_t write(UserPtr<const void*> buf, size_t len);

protected:
	// File operations with C-like polymorphism. Member m_fops is modified by
	// inherited classes to set one of these. That way polymorphism is achieved
	// while avoiding dynamic memory allocations
	struct file_ops {
		int (File::*do_stat)(UserPtr<struct stat*> stat_ptr) const;
		ssize_t (File::*do_read)(UserPtr<void*> buf, size_t len);
		ssize_t (File::*do_write)(UserPtr<const void*> buf, size_t len);
	};
	static const file_ops fops_regular;
	static const file_ops fops_stdin;
	static const file_ops fops_stdout;
	static const file_ops fops_stderr;
	file_ops m_fops;

private:
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

	// Actual implementations of file operations
	int do_stat_regular(UserPtr<struct stat*> stat_ptr) const;
	int do_stat_stdout(UserPtr<struct stat*> stat_ptr) const;
	ssize_t do_read_regular(UserPtr<void*> buf, size_t len);
	ssize_t do_write_stdout(UserPtr<const void*> buf, size_t len);
};

class FileStdin : public File {
public:
	FileStdin();
};

class FileStdout : public File {
public:
	FileStdout();
};

class FileStderr : public File {
public:
	FileStderr();
};

#endif