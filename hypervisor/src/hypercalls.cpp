#include <iostream>
#include <linux/limits.h>
#include "vm.h"

using namespace std;

// Keep this the same as in the kernel!
enum Hypercall : size_t {
	Test,
	Alloc,
	Ready,
	Print,
	GetElfPath,
	EndRun,
};

vaddr_t Vm::do_hc_alloc(vsize_t size) {
	printf("hc alloc %lu\n", size);
	return m_mmu.alloc(size, PDE64_RW);
}

void Vm::do_hc_print(vaddr_t msg_addr) {
	string msg = m_mmu.read_string(msg_addr);
	cout << "[KERNEL] " << msg;
}

void Vm::do_hc_get_elf_path(vaddr_t buf_addr, vsize_t bufsize) {
	// Get path, convert it to absolute and write it to memory
	char abspath[PATH_MAX];
	ERROR_ON(!realpath(m_elf.path().c_str(), abspath), "readlink: realpath");
	size_t len = strlen(abspath) + 1; // include null byte
	ASSERT(len <= bufsize, "hc get elf path: small buffer");
	m_mmu.write_mem(buf_addr, abspath, len);
}

void Vm::handle_hypercall() {
	uint64_t ret = 0;
	switch (m_regs->rax) {
		case Hypercall::Test:
			die("Hypercall test, arg=0x%llx\n", m_regs->rdi);
		case Hypercall::Alloc:
			ret = do_hc_alloc(m_regs->rdi);
			break;
		case Hypercall::Ready:
			m_running = false;
			return;
		case Hypercall::Print:
			do_hc_print(m_regs->rdi);
			break;
		case Hypercall::GetElfPath:
			do_hc_get_elf_path(m_regs->rdi, m_regs->rsi);
			break;
		default:
			ASSERT(false, "unknown hypercall: %llu", m_regs->rax);
	}

	m_regs->rax = ret;
	set_regs_dirty();
}