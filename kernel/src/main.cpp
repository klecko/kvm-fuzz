#include <unistd.h>
#include <elf.h>
#include "user.h"
#include "init.h"
#include "mem.h"
#include "asm.h"
#include "vector"

void init_file_contents(size_t n) {
	// For each file, get its filename and its length and allocate a buffer
	// for the file content. Submit the address of the buffer and the address of
	// the length to the hypervisor, which will write file contents into the
	// buffer and real file length into the length.
	void* buf;
	size_t size;
	char filename[PATH_MAX];
	for (size_t i = 0; i < n; i++) {
		hc_get_file_name(i, filename);
		size = hc_get_file_len(i);
		buf = kmalloc(size);
		struct iovec& iov = m_file_contents[string(filename)];
		iov.iov_base = buf;
		iov.iov_len  = size;
		hc_set_file_pointers(i, iov.iov_base, &iov.iov_len);
	}
}

const char* environ[] = {
	"SHELL=/bin/bash",
	"EDITOR=vim",
	"PWD=/home/klecko/",
	"LOGNAME=klecko",
	"HOME=/home/klecko",
	"USERNAME=klecko",
	"TERM=xterm-256color",
	"PATH=/home/klecko/.cargo/bin:/home/klecko/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/home/klecko/.local/bin/:/opt/x86_64-elf/bin/:/home/klecko/zig/",
	// If these are set, file /usr/lib/locale/locale-archive has to be loaded
	// in the hypervisor
	//"LC_NAME=es_ES.UTF-8",
	//"LANG=es_ES.UTF-8",
	"_=/usr/bin/env",
};
const int environ_n = sizeof(environ)/sizeof(*environ);

void* prepare_user_stack(int argc, char** argv, const VmInfo& info) {
	// Allocate stack
	uint8_t* user_stack = (uint8_t*)Mem::Virt::alloc_user_stack();

	user_stack -= 16;
	memset(user_stack, 0, 16);

	// Random bytes for auxv
	user_stack -= 16;
	uint8_t* random_bytes = user_stack;
	for (size_t i = 0; i < 16; i++)
		random_bytes[i] = i;

	// Write argv strings saving pointers to each arg
	char* argv_addrs[argc];
	size_t arg_len;
	for (int i = 0; i < argc; i++) {
		arg_len = strlen(argv[i]) + 1;
		user_stack -= arg_len;
		memcpy(user_stack, argv[i], arg_len);
		argv_addrs[i] = (char*)user_stack;
	}

	// Write environ strings saving pointers to each env
	char* environ_addrs[environ_n];
	for (int i = 0; i < environ_n; i++) {
		arg_len = strlen(environ[i]) + 1;
		user_stack -= arg_len;
		memcpy(user_stack, environ[i], arg_len);
		environ_addrs[i] = (char*)user_stack;
	}

	// Align stack
	user_stack = (uint8_t*)((uintptr_t)user_stack & ~0xF);
	user_stack -= 8;

	// Set up auxp
	// Note for future Klecko: the only mandatory one seems to be AT_RANDOM.
	// Stop implementing these in an attempt to fix something.
	// Your bug is in another castle.
	Elf64_auxv_t auxv[] = {
		{AT_PHDR,   (uint64_t)info.elf_load_addr + info.phinfo.e_phoff},
		{AT_PHENT,  info.phinfo.e_phentsize},
		{AT_PHNUM,  info.phinfo.e_phnum},
		{AT_PAGESZ, PAGE_SIZE},
		{AT_BASE,   (uint64_t)info.interp_base},
		{AT_ENTRY,  (uint64_t)info.elf_entry},
		{AT_RANDOM, (uint64_t)random_bytes},
		{AT_EXECFN, (uint64_t)argv_addrs[0]},
		{AT_UID,	0},
		{AT_EUID,	0},
		{AT_GID,	0},
		{AT_EGID,	0},
		{AT_NULL,   0}
	};
	user_stack -= sizeof(auxv);
	memcpy(user_stack, &auxv, sizeof(auxv));

	// Set up envp
	user_stack -= sizeof(environ_addrs) + 8;
	memcpy(user_stack, environ_addrs, sizeof(environ_addrs));
	((uint64_t*)user_stack)[environ_n] = 0;

	// Set up argv
	user_stack -= sizeof(argv_addrs) + 8;
	memcpy(user_stack, argv_addrs, sizeof(argv_addrs));
	((uint64_t*)user_stack)[argc] = 0;

	// Set up argc
	user_stack -= 8;
	*(uint64_t*)user_stack = argc;

	dbgprintf("ARGS:\n");
	for (int i = 0; i < argc; i++)
		dbgprintf("\t%d: %s\n", i, argv_addrs[i]);

	return user_stack;
}

void init_performance_counter() {
	// Set perfomance counter CTR0 (which counts number of instructions)
	// to only count when in user mode
	wrmsr(MSR_FIXED_CTR_CTRL, 2);

	// Enable CTR0
	wrmsr(MSR_PERF_GLOBAL_CTRL, 1ULL << 32);
}

extern "C" void kmain(int argc, char** argv) {
	// Init kernel stuff
	Mem::Phys::init_memory();
	init_tss();
	init_gdt();
	init_idt();
	init_syscall();
#ifdef ENABLE_INSTRUCTION_COUNT
	init_performance_counter();
#endif

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

	dbgprintf("Elf path: %s\n", m_elf_path.c_str());
	dbgprintf("Brk: %p\n", m_brk);
	dbgprintf("Files: %d\n", m_file_contents.size());
	for (auto v : m_file_contents) {
		dbgprintf("\t%s, length %lu\n", v.f.c_str(), v.s.iov_len);
	}

	void* user_stack = prepare_user_stack(argc, argv, info);
	printf("Jumping to user at %p!\n", info.user_entry);
	jump_to_user(info.user_entry, user_stack);
}