#include <unistd.h>
#include "kernel.h"
#include "libcpp.h"
#include "hypercalls.h"
#include "syscall_str.h"
#include "tss.h"
#include "gdt.h"
#include "idt.h"

void* Kernel::m_kernel_stack;
void* Kernel::m_user_stack;
string Kernel::m_elf_path;
void* Kernel::m_brk;
void* Kernel::m_min_brk;
unordered_map<int, File> Kernel::m_open_files;
unordered_map<string, struct iovec> Kernel::m_file_contents;

TSSEntry tss;
GlobalDescriptor g_gdt[N_GDT_ENTRIES];
InterruptDescriptor g_idt[N_IDT_ENTRIES];

void Kernel::init() {
	// Init kernel stuff
	save_kernel_stack();
	init_tss();
	init_gdt();
	init_idt();
	register_syscall();

	printf("Hello from kernel\n");

	// Let's init kernel state. We'll need help from the hypervisor
	VmInfo info;
	hc_get_info(&info);

	// First, call constructors
	for (size_t i = 0; i < info.num_constructors; i++) {
		info.constructors[i]();
	}

	// Initialize data members
	m_user_stack = 0;
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

void Kernel::init_tss() {
	// The TSS is referenced by a TSSDescriptor in the GDT. The selector of this
	// TSSDescriptor is loaded into the TSR when loading the GDT.
	static_assert(sizeof(TSSEntry) == 104);

	// Stack used when switching from ring3 to ring0 because of an interruption
	tss.rsp0 = (uint64_t)m_kernel_stack;

	// Stack used when an exception occurs in ring 0
	// (requires ist field in IDT to be 1) TODO
	tss.ist1 = (uint64_t)m_kernel_stack;
	tss.iopb = sizeof(TSSEntry);
}

void Kernel::init_gdt() {
	static_assert(sizeof(GlobalDescriptor) == 0x8);
	static_assert(sizeof(TSSDescriptor) == 0x10);

	// Null descriptor is at offset 0x00
	// Kernel code, offset 0x08
	g_gdt[1].set_code();
	g_gdt[1].set_dpl(0);

	// Kernel data, offset 0x10
	g_gdt[2].set_data();
	g_gdt[2].set_dpl(0);

	// User data, offset 0x18
	g_gdt[3].set_data();
	g_gdt[3].set_dpl(3);

	// User code, offset 0x20
	g_gdt[4].set_code();
	g_gdt[4].set_dpl(3);

	// TSS, offset 0x28. Ugly memcpy because TSSDescriptor is twice the size of
	// GlobalDescriptor
	TSSDescriptor tss_descriptor;
	tss_descriptor.set_base((uint64_t)&tss);
	memcpy(&g_gdt[5], &tss_descriptor, sizeof(tss_descriptor));

	GDTPtr gdt_ptr = {
		.size = sizeof(g_gdt) - 1,
		.offset = (uint64_t)g_gdt
	};
	gdt_ptr.load();

	printf("GDT set\n");
}

void test_handler() {
	printf("hello world\n");
	hlt();
}

void Kernel::init_idt() {
	static_assert(sizeof(InterruptDescriptor) == 16);
	for (size_t i = 0; i < N_IDT_ENTRIES; i++) {
		g_idt[i].set_offset(test_handler);
		g_idt[i].set_selector(SEGMENT_SELECTOR_KCODE);
		g_idt[i].set_dpl(3);
		g_idt[i].set_present();
		g_idt[i].set_type(InterruptDescriptor::Type::Interrupt);
	}

	IDTR idtr = {
		.size   = sizeof(g_idt) - 1,
		.offset = (uint64_t)g_idt
	};
	idtr.load();

	printf("IDT set\n");
}

void Kernel::wrmsr(unsigned int msr, uint64_t val) {
	asm volatile(
		"wrmsr"
		:
		: "c" (msr),
		  "a" (val & 0xFFFFFFFF),
		  "d" (val >> 32)
		: "memory"
	);
}

uint64_t Kernel::rdmsr(unsigned int msr) {
	uint32_t hi, lo;
	asm volatile(
		"rdmsr"
		: "=d" (hi),
		  "=a" (lo)
		: "c" (msr)
		: "memory"
	);
	return ((uint64_t)hi << 32) | lo;
}

void Kernel::register_syscall() {
	/*
	[SYSCALL]
	CS.selector = STAR 47:32
	SS.selector = STAR 47:32 + 8

	[SYSRET 64 BITS]
	CS.selector = STAR 63:48 + 16
	SS.selector = STAR 63:48 + 8
	*/
	static_assert(SEGMENT_SELECTOR_KDATA == SEGMENT_SELECTOR_KCODE + 8);
	static_assert(SEGMENT_SELECTOR_UCODE == SEGMENT_SELECTOR_UDATA + 8);
	uint64_t star = 0;
	star |= ((uint64_t)SEGMENT_SELECTOR_KCODE << 32);        // for syscall
	star |= ((uint64_t)(SEGMENT_SELECTOR_UDATA - 8) << 48);  // for sysret
	wrmsr(MSR_STAR, star);
	wrmsr(MSR_LSTAR, (uint64_t)syscall_entry);
	wrmsr(MSR_SYSCALL_MASK, 0x3f7fd5);

	printf("Syscall handlet set\n");
}

void Kernel::init_file_contents(size_t n) {
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

// Warning: -fpie is needed for these to use relative addressing so it doesn't
// dirty any other register
__attribute__((__always_inline__)) inline
void Kernel::save_kernel_stack() {
	asm volatile("mov %[kernel_stack], rsp;" : [kernel_stack] "=m"(m_kernel_stack) : :);
}

__attribute__((__always_inline__)) inline
void Kernel::save_user_stack() {
	asm volatile("mov %[user_stack], rsp;" : [user_stack] "=m"(m_user_stack) : :);
}

__attribute__((__always_inline__)) inline
void Kernel::restore_kernel_stack() {
	asm volatile("mov rsp, %[kernel_stack];" : [kernel_stack] "=m"(m_kernel_stack) : :);
}

__attribute__((__always_inline__)) inline
void Kernel::restore_user_stack() {
	asm volatile("mov rsp, %[user_stack];" : [user_stack] "=m"(m_user_stack) : :);
}


__attribute__((naked))
void Kernel::syscall_entry() {
	//asm volatile("hlt");
	save_user_stack();
	restore_kernel_stack();

	asm volatile(
	// Save non-callee-saved registers. This includes rcx (return address)
	// and r11 (rflags)
		"push rdi;"
		"push rsi;"
		"push rdx;"
		"push rcx;"
		"push r8;"
		"push r9;"
		"push r10;"
		"push r11;"

	// The forth argument is set in r10. We need to move it to r10 to conform to
	// C ABI. Arguments should be in: rdi, rsi, rdx, rcx, r8, r9
		"mov rcx, r10;"

	// Handle syscall. Return value will be held in rax
		"call %[handler];"

	// Restore registers
		"pop r11;"
		"pop r10;"
		"pop r9;"
		"pop r8;"
		"pop rcx;"
		"pop rdx;"
		"pop rsi;"
		"pop rdi;"
	:
	: [handler] "i"(_handle_syscall) // Inmediate, so it doesn't dirty regs
	:
	);

	//save_kernel_stack();
	restore_user_stack();
	//asm volatile("hlt");
	asm volatile("sysretq");
}

// This needs to be in the same file as syscall_entry, so it can be called
// from there without dirtying any reg
uint64_t Kernel::_handle_syscall(uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                 uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	register int nr asm("eax");
	return Kernel::handle_syscall(nr, arg0, arg1, arg2, arg3, arg4, arg5);
}