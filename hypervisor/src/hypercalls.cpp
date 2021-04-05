#include <iostream>
#include <linux/limits.h>
#include <sys/mman.h>
#include "vm.h"

using namespace std;

// Keep this the same as in the kernel!
enum Hypercall : size_t {
	Test,
	Print,
	GetMemInfo,
	GetKernelBrk,
	GetInfo,
	GetFileLen,
	GetFileName,
	SetFilePointers,
	PrintStacktrace,
	Fault,
	EndRun,
};

void Vm::do_hc_print(vaddr_t msg_addr) {
	string msg = m_mmu.read_string(msg_addr);
	cout << "[KERNEL] " << msg;
}

void Vm::do_hc_get_mem_info(vaddr_t mem_start_addr, vaddr_t mem_length_addr) {
	paddr_t next_frame_alloc = m_mmu.next_frame_alloc();
	m_mmu.write<vaddr_t>(mem_start_addr, next_frame_alloc);
	m_mmu.write<vaddr_t>(mem_length_addr, m_mmu.size());

	// From this point on, kernel is in charge of managing physical memory
	// and not us
	m_mmu.disable_allocations();
}

vaddr_t Vm::do_hc_get_kernel_brk() {
	return m_kernel.initial_brk();
}

// Keep this the same as in the kernel
struct VmInfo {
	char elf_path[PATH_MAX];
	vaddr_t brk;
	vsize_t num_files;
	vaddr_t constructors;
	vsize_t num_constructors;
	vaddr_t user_entry;
	vaddr_t elf_entry;
	vaddr_t elf_load_addr;
	vaddr_t interp_base;
	phinfo_t phinfo;
};

void Vm::do_hc_get_info(vaddr_t info_addr) {
	// Get absolute elf path, brk and other stuff
	VmInfo info;
	ERROR_ON(!realpath(m_elf.path().c_str(), info.elf_path), "elf realpath");
	info.brk = m_elf.initial_brk();
	info.num_files = m_file_contents.size();

	info.constructors = 0;
	info.num_constructors = 0;
	for (section_t& section : m_kernel.sections()) {
		if (section.name == ".ctors") {
			info.constructors = section.addr;
			info.num_constructors = section.size / sizeof(vaddr_t);
			break;
		}
	}

	info.user_entry    = (m_interpreter ? m_interpreter->entry() : m_elf.entry());
	info.elf_entry     = m_elf.entry();
	info.elf_load_addr = m_elf.load_addr();
	info.interp_base   = (m_interpreter ? m_interpreter->base() : 0);
	info.phinfo        = m_elf.phinfo();

	m_mmu.write(info_addr, info);
}

vsize_t Vm::do_hc_get_file_len(size_t n) {
	ASSERT(n < m_file_contents.size(), "OOB n: %lu", n);
	auto it = m_file_contents.begin();
	advance(it, n);
	dbgprintf("kernel got file length for file %s: %lu\n", it->first.c_str(),
	          it->second.length);
	return it->second.length;
}

void Vm::do_hc_get_file_name(size_t n, vaddr_t buf_addr) {
	ASSERT(n < m_file_contents.size(), "OOB n: %lu", n);
	auto it = m_file_contents.begin();
	advance(it, n);
	m_mmu.write_mem(buf_addr, it->first.c_str(), it->first.size() + 1);
}

void Vm::do_hc_set_file_pointers(size_t n, vaddr_t data_addr,
                                 vaddr_t length_addr) {
	// Save pointers and write the data and the length to them. This will be
	// repeated each time `set_file` is called
	ASSERT(n < m_file_contents.size(), "OOB n: %lu", n);
	auto it = m_file_contents.begin();
	advance(it, n);
	file_t& file_info = it->second;
	file_info.guest_data_addr = data_addr;
	file_info.guest_length_addr = length_addr;
	m_mmu.write_mem(data_addr, file_info.data, file_info.length);
	m_mmu.write<size_t>(length_addr, file_info.length);
	dbgprintf("kernel set pointers for file %s: 0x%lx 0x%lx\n",
	          it->first.c_str(), data_addr, length_addr);
}

void Vm::do_hc_print_stacktrace(vaddr_t rsp, vaddr_t rip, vaddr_t rbp) {
	// For now we set just rsp, rip and rbp, which seem to be the only
	// ones needed in most situations, and initialize the others to 0.
	// If print_stacktrace fails, we may need to request more registers
	// from guest.
	kvm_regs regs = {
		.rsp = rsp,
		.rbp = rbp,
		.rip = rip,
	};
	print_stacktrace(regs);
}

void Vm::do_hc_fault(vaddr_t fault_addr, uint64_t instr_executed) {
	m_fault = m_mmu.read<FaultInfo>(fault_addr);
	set_instructions_executed(instr_executed);
}

void Vm::do_hc_end_run(uint64_t instr_executed) {
	set_instructions_executed(instr_executed);
}

void Vm::handle_hypercall(RunEndReason& reason) {
	uint64_t ret = 0;
	switch (m_regs->rax) {
		case Hypercall::Test:
			die("Hypercall test, arg=0x%llx\n", m_regs->rdi);
		case Hypercall::Print:
			do_hc_print(m_regs->rdi);
			break;
		case Hypercall::GetMemInfo:
			do_hc_get_mem_info(m_regs->rdi, m_regs->rsi);
			break;
		case Hypercall::GetKernelBrk:
			ret = do_hc_get_kernel_brk();
			break;
		case Hypercall::GetInfo:
			do_hc_get_info(m_regs->rdi);
			break;
		case Hypercall::GetFileLen:
			ret = do_hc_get_file_len(m_regs->rdi);
			break;
		case Hypercall::GetFileName:
			do_hc_get_file_name(m_regs->rdi, m_regs->rsi);
			break;
		case Hypercall::SetFilePointers:
			do_hc_set_file_pointers(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case Hypercall::PrintStacktrace:
			do_hc_print_stacktrace(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case Hypercall::Fault:
			do_hc_fault(m_regs->rdi, m_regs->rsi);
			m_running = false;
			reason = RunEndReason::Crash;
			break;
		case Hypercall::EndRun:
			do_hc_end_run(m_regs->rdi);
			m_running = false;
			reason = RunEndReason::Exit;
			break;
		default:
			ASSERT(false, "unknown hypercall: %llu", m_regs->rax);
	}

	m_regs->rax = ret;
	set_regs_dirty();
}