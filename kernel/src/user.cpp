#include "common.h"
#include "process.h"
#include "linux/auxvec.h"

// TODO: LOADER

static const char* environ[] = {
	"SHELL=/bin/bash",
	"EDITOR=vim",
	"PWD=/home/klecko/",
	"LOGNAME=klecko",
	"HOME=/home/klecko",
	"USERNAME=klecko",
	"TERM=xterm-256color",
	"PATH=/home/klecko/.cargo/bin:/home/klecko/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/home/klecko/.local/bin/:/opt/x86_64-elf/bin/:/home/klecko/zig/",
	// "LD_DEBUG=files", // show base address of each library
	// "LD_SHOW_AUXV=1", // dump auxv vector
	// If these are set, file /usr/lib/locale/locale-archive has to be loaded
	// in the hypervisor
	//"LC_NAME=es_ES.UTF-8",
	//"LANG=es_ES.UTF-8",
	"_=/usr/bin/env",
};
static const int environ_n = sizeof(environ)/sizeof(*environ);

static uint8_t* setup_user_stack(uint8_t* user_stack, int argc, char** argv,
                                 const VmInfo& info)
{
	user_stack -= 16;
	memset(user_stack, 0, 16);

	// Random bytes for auxv
	user_stack -= 16;
	uint8_t* random_bytes = user_stack;
	for (size_t i = 0; i < 16; i++)
		random_bytes[i] = i;

	// Platform for auxv
	const char platform_string[] = "x86_64";
	user_stack -= sizeof(platform_string) + 1;
	memcpy(user_stack, platform_string, sizeof(platform_string) + 1);
	uint8_t* platform = user_stack;

	// Align stack
	user_stack = (uint8_t*)((uintptr_t)user_stack & ~0xF);

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
	if (((sizeof(environ_addrs) + 8 + sizeof(argv_addrs) + 8) & 0xF) == 0)
		user_stack -= 8;

	// Set up auxp
	// Note for future Klecko: the only mandatory one for static binaries seems
	// to be AT_RANDOM. Stop implementing these in an attempt to fix something.
	// Your bug is in another castle.
	struct {
		uint64_t type;
		uint64_t value;
	} auxv[] = {
		{AT_PHDR,     (uint64_t)info.elf_load_addr + info.phinfo.e_phoff},
		{AT_PHENT,    info.phinfo.e_phentsize},
		{AT_PHNUM,    info.phinfo.e_phnum},
		{AT_PAGESZ,   PAGE_SIZE},
		{AT_BASE,     (uint64_t)info.interp_base},
		{AT_FLAGS,    0},
		{AT_ENTRY,    (uint64_t)info.elf_entry},
		{AT_RANDOM,   (uint64_t)random_bytes},
		{AT_EXECFN,   (uint64_t)argv_addrs[0]},
		{AT_PLATFORM, (uint64_t)platform},
		{AT_SECURE,   0},
		{AT_UID,      0},
		{AT_EUID,     0},
		{AT_GID,      0},
		{AT_EGID,     0},
		{AT_NULL,     0}
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

	ASSERT(((uintptr_t)user_stack & ~0xF) == (uintptr_t)user_stack,
	       "user stack not properly aligned: %p", user_stack);

	return user_stack;
}

inline void jump_to_user(void* entry, void* stack) {
	asm volatile (
		// Set user stack, RIP and RFLAGS
		"mov rsp, %[rsp];"
		"mov rcx, %[entry];"
		"mov r11, 0x202;"

		// Clear every other register
		"xor rax, rax;"
		"xor rbx, rbx;"
		"xor rdx, rdx;"
		"xor rdi, rdi;"
		"xor rsi, rsi;"
		"xor rbp, rbp;"
		"xor r8, r8;"
		"xor r9, r9;"
		"xor r10, r10;"
		"xor r12, r12;"
		"xor r13, r13;"
		"xor r14, r14;"
		"xor r15, r15;"

		// Jump to user
		"sysretq;"
		:
		: [rsp]   "a" (stack),
		  [entry] "b" (entry)
		:
	);
}

void Process::start_user(int argc, char** argv, const VmInfo& info) {
	// Allocate stack
	static const uintptr_t USER_STACK_ADDR = 0x800000000000;
	static const size_t    USER_STACK_SIZE = 0x10000;
	Range range(USER_STACK_ADDR - USER_STACK_SIZE, USER_STACK_SIZE);
	bool success = m_space.map_range(range, MemPerms::Read | MemPerms::Write);
	ASSERT(success, "error mapping user stack");

	// Set it up
	uint8_t* user_stack = (uint8_t*)USER_STACK_ADDR;
	user_stack = setup_user_stack(user_stack, argc, argv, info);

	// Jump to user code
	printf("Jumping to user at %p!\n", info.user_entry);
	jump_to_user(info.user_entry, user_stack);
}