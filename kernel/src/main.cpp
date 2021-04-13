#include "user.h"
#include "mem/mem.h"
#include "x86/asm.h"
#include "x86/apic/apic.h"
#include "x86/gdt/gdt.h"
#include "x86/idt/idt.h"
#include "x86/syscall/syscall.h"
#include "x86/perf/perf.h"
#include "fs/file_manager.h"
#include "process.h"
#include "scheduler.h"

extern "C" void kmain(int argc, char** argv) {
	// Init kernel stuff
	Mem::Phys::init_memory();
	GDT::init();
	IDT::init();
	Syscall::init();
	APIC::init();
	Perf::init();

	printf("Hello from kernel\n");

	// Let's init kernel state. We'll need help from the hypervisor
	VmInfo info;
	hc_get_info(&info);

	// First, call constructors
	for (size_t i = 0; i < info.num_constructors; i++) {
		info.constructors[i]();
	}

	// Initialize data members
	FileManager::init(info.num_files);
	m_term     = info.term;

	Process process(info);

	dbgprintf("Elf path: %s\n", m_elf_path.c_str());
	dbgprintf("Brk: %p\n", m_brk);

	start_user(argc, argv, info);
}