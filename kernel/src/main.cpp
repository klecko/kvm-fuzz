#include <unistd.h>
#include "kernel.h"
#include "init.h"

// Global kernel state
string m_elf_path;
void* m_brk;
void* m_min_brk;
unordered_map<int, File> m_open_files;
unordered_map<string, struct iovec> m_file_contents;

void init_file_contents(size_t n) {
	// For each file, get its filename and its length, allocate a buffer
	// and submit it to the hypervisor, which will write the file content to it
	void* buf;
	size_t size;
	char filename[PATH_MAX];
	for (size_t i = 0; i < n; i++) {
		hc_get_file_name(i, filename);
		size = hc_get_file_len(i);
		buf = kmalloc(size);
		hc_set_file_buf(i, buf);
		m_file_contents[string(filename)] = {
			.iov_base = buf,
			.iov_len  = size,
		};
	}
}

extern "C" void kmain() {
	// Init kernel stuff
	init_tss();
	init_gdt();
	init_idt();
	init_syscall();

	printf("Hello from kernel\n");

	// Let's init kernel state. We'll need help from the hypervisor
	VmInfo info;
	hc_get_info(&info);

	// First, call constructors
	for (size_t i = 0; i < info.num_constructors; i++) {
		info.constructors[i]();
	}

	// Initialize data members
	m_elf_path   = string(info.elf_path);
	m_brk        = info.brk;
	m_min_brk    = m_brk;
	m_open_files[STDIN_FILENO]  = FileStdin();
	m_open_files[STDOUT_FILENO] = FileStdout();
	m_open_files[STDERR_FILENO] = FileStderr();
	init_file_contents(info.num_files);

	printf("Elf path: %s\n", m_elf_path.c_str());
	printf("Brk: 0x%lx\n", m_brk);
	printf("Files: %d\n", m_file_contents.size());
	for (auto v : m_file_contents) {
		printf("\t%s, length %lu\n", v.f.c_str(), v.s.iov_len);
	}

	// We are ready
	hc_ready();
}