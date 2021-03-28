#ifndef _FILE_H
#define _FILE_H

#include <sys/stat.h>
#include "common.h"

// Used by stat. Fstat should use the corresponding method in File
void stat_regular(struct stat* statbuf, size_t filesize, unsigned long inode);
void stat_stdout(struct stat* statbuf);

class File;
struct file_ops {
	void (File::*do_stat)(struct stat* statbuf) const;
	size_t (File::*do_read)(void* buf, size_t len);
	size_t (File::*do_write)(const void* buf, size_t len);
};

class File {
public:
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
	void stat(struct stat* statbuf) const;
	size_t read(void* buf, size_t len);
	size_t write(const void* buf, size_t len);

protected:
	// File operations with C-like polymorphism. Member m_fops is modified by
	// inherited classes to set one of these. That way polymorphism is achieved
	// while avoiding dynamic memory allocations
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
	void   do_stat_regular(struct stat* statbuf) const;
	void   do_stat_stdout(struct stat* statbuf) const;
	size_t do_read_regular(void* buf, size_t len);
	size_t do_write_stdout(const void* buf, size_t len);
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