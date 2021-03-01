#include <iostream>
#include <linux/limits.h>
#include <sys/mman.h>
#include "vm.h"

using namespace std;

// Keep this the same as in the kernel!
enum Hypercall : size_t {
	Test,
	Mmap,
	Ready,
	Print,
	GetInfo,
	EndRun,
};

vaddr_t Vm::do_hc_mmap(vaddr_t addr, vsize_t size, uint64_t page_flags, int flags) {
	int supported_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
	ASSERT((flags & supported_flags) == flags, "flags 0x%x", flags);
	ASSERT(flags & MAP_PRIVATE, "shared mapping");
	ASSERT(flags & MAP_ANONYMOUS, "file backed mapping");
	ASSERT((size & PTL1_MASK) == size, "not aligned size %lx", size);
	uint64_t ret = 0;
	if (flags & MAP_FIXED) {
		m_mmu.alloc(addr, size, page_flags);
		ret = addr;
	} else {
		ret = m_mmu.alloc(size, page_flags);
	}
	dbgprintf("hc alloc %lu at 0x%lx with page flags 0x%lx\n", size, ret, page_flags);
	return ret;
}

void Vm::do_hc_print(vaddr_t msg_addr) {
	string msg = m_mmu.read_string(msg_addr);
	cout << "[KERNEL] " << msg;
}

struct VmInfo {
	char elf_path[PATH_MAX];
	vaddr_t brk;
};

void Vm::do_hc_get_info(vaddr_t info_addr) {
	// Get absolute elf path, brk and other stuff
	VmInfo info;
	ERROR_ON(!realpath(m_elf.path().c_str(), info.elf_path), "elf realpath");
	info.brk = m_elf.initial_brk();
	m_mmu.write(info_addr, info);
}

void Vm::handle_hypercall() {
	uint64_t ret = 0;
	switch (m_regs->rax) {
		case Hypercall::Test:
			die("Hypercall test, arg=0x%llx\n", m_regs->rdi);
		case Hypercall::Mmap:
			ret = do_hc_mmap(m_regs->rdi, m_regs->rsi, m_regs->rdx, m_regs->rcx);
			break;
		case Hypercall::Ready:
			m_running = false;
			return;
		case Hypercall::Print:
			do_hc_print(m_regs->rdi);
			break;
		case Hypercall::GetInfo:
			do_hc_get_info(m_regs->rdi);
			break;
		default:
			ASSERT(false, "unknown hypercall: %llu", m_regs->rax);
	}

	m_regs->rax = ret;
	set_regs_dirty();
}