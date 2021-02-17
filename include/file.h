#include <sys/stat.h>
#include "mmu.h"

// Used by stat. Fstat should use the corresponding method in File
void stat_regular(vaddr_t stat_addr, vsize_t filesize, Mmu& mmu);
void stat_stdout(vaddr_t stat_addr, Mmu& mmu);

class File;
struct file_ops {
	void (File::*do_stat)(vaddr_t stat_addr, Mmu& mmu);
	vsize_t (File::*do_read)(vaddr_t buf_addr, vsize_t len, Mmu& mmu);
	vsize_t (File::*do_write)(vaddr_t buf_addr, vsize_t len, Mmu& mmu);
};

class File {
public:
	File(uint32_t flags = 0, const char* buf = NULL, vsize_t size = 0);

	uint32_t flags();
	void set_flags(uint32_t flags);
	const char* cursor();
	bool    is_readable();
	bool    is_writable();
	vsize_t size();
	vsize_t offset();
	void    set_offset(vsize_t offset);

	// File operations
	void    stat(vaddr_t stat_addr, Mmu& mmu);
	vsize_t read(vaddr_t buf_addr, vsize_t len, Mmu& mmu);
	vsize_t write(vaddr_t buf_addr, vsize_t len, Mmu& mmu);

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
	vsize_t m_size;

	// Cursor offset
	vsize_t m_offset;

	// Attempt to move the cursor. Returns the real increment performed,
	// emulating read or write
	vsize_t move_cursor(vsize_t increment);

	// Actual implementations of file operations
	void    do_stat_regular(vaddr_t stat_addr, Mmu& mmu);
	void    do_stat_stdout(vaddr_t stat_addr, Mmu& mmu);
	vsize_t do_read_regular(vaddr_t buf_addr, vsize_t len, Mmu& mmu);
	vsize_t do_write_stdout(vaddr_t buf_addr, vsize_t len, Mmu& mmu);
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