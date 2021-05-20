#include "mem/pmm.h"
#include "mem/vmm.h"
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
	// Let's init kernel state. We'll need help from the hypervisor
	VmInfo info;
	hc_get_info(&info);

	// First, call constructors as soon as we can
	for (size_t i = 0; i < info.num_constructors; i++) {
		info.constructors[i]();
	}

	// Init kernel stuff
	GDT::init();
	IDT::init();
	PMM::init();
	VMM::init();
	Perf::init();
	APIC::init();
	Syscall::init();
	FileManager::init(info.num_files);

	printf("Hello from kernel\n");

	// m_term     = info.term;

	Process process(info);
	Scheduler::init(process);
	process.start_user(argc, argv, info);
}