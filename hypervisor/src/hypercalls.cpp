#include <iostream>
#include <linux/limits.h>
#include <sys/mman.h>
#include <termios.h>
#include "vm.h"

using namespace std;

// Keep this the same as in the kernel
enum Hypercall : size_t {
	Test,
	Print,
	GetMemInfo,
	GetKernelBrk,
	GetInfo,
	GetFileLen,
	GetFileName,
	SubmitFilePointers,
	SubmitTimeoutPointers,
	PrintStacktrace,
	LoadLibrary,
	EndRun,
};

// Keep this the same as in the kernel
struct StacktraceRegs {
	vaddr_t rsp;
	vaddr_t rbp;
	vaddr_t rip;
};

void Vm::do_hc_print(vaddr_t msg_addr) {
	string msg = m_mmu.read_string(msg_addr);
	cout << "[KERNEL] " << msg;
}

// Keep this the same as in the kernel
struct MemInfo {
	paddr_t mem_start;
	psize_t mem_length;
	vaddr_t physmap_vaddr;
};

void Vm::do_hc_get_mem_info(vaddr_t mem_info_addr) {
	MemInfo info = {
		.mem_start = m_mmu.next_frame_alloc(),
		.mem_length = m_mmu.size(),
		.physmap_vaddr = Mmu::PHYSMAP_ADDR,
	};
	m_mmu.write(mem_info_addr, info);

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
	vaddr_t user_entry;
	vaddr_t elf_entry;
	vaddr_t elf_load_addr;
	vaddr_t interp_start;
	vaddr_t interp_end;
	phinfo_t phinfo;
	struct termios term;
};

void Vm::do_hc_get_info(vaddr_t info_addr) {
	// Get absolute elf path, brk and other stuff
	VmInfo info;
	ERROR_ON(!realpath(m_elf.path().c_str(), info.elf_path), "elf realpath");
	info.brk           = m_elf.initial_brk();
	info.num_files     = m_file_contents.size();
	info.user_entry    = (m_interpreter ? m_interpreter->entry() : m_elf.entry());
	info.elf_entry     = m_elf.entry();
	info.elf_load_addr = m_elf.load_addr();
	info.interp_start  = (m_interpreter ? m_interpreter->load_addr() : 0);
	info.interp_end    = (m_interpreter ? info.interp_start + m_interpreter->size() : 0);
	info.phinfo        = m_elf.phinfo();

	// Make sure our struct termios corresponds to the one used by the kernel
	#if !defined(_HAVE_STRUCT_TERMIOS_C_ISPEED) ||   \
	    !defined(_HAVE_STRUCT_TERMIOS_C_OSPEED)
	#error struct termios in hypervisor doesn't have ispeed and ospeed?
	#endif
	tcgetattr(STDOUT_FILENO, &info.term);

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

void Vm::do_hc_submit_file_pointers(size_t n, vaddr_t data_addr,
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

void Vm::do_hc_submit_timeout_pointers(vaddr_t timer_addr, vaddr_t timeout_addr) {
	m_timer_addr   = timer_addr;
	m_timeout_addr = timeout_addr;
}

void Vm::do_hc_print_stacktrace(vaddr_t stacktrace_regs_addr) {
	// For now we set just rsp, rip and rbp, which seem to be the only
	// ones needed in most situations, and initialize the others to 0.
	// If print_stacktrace fails, we may need to request more registers
	// from guest.
	StacktraceRegs stacktrace_regs = m_mmu.read<StacktraceRegs>(stacktrace_regs_addr);
	kvm_regs regs = {
		.rsp = stacktrace_regs.rsp,
		.rbp = stacktrace_regs.rbp,
		.rip = stacktrace_regs.rip,
	};
	print_stacktrace(regs);
}

void Vm::do_hc_load_library(vaddr_t filename_ptr, vsize_t filename_len,
                            vaddr_t load_addr)
{
	string filename = m_mmu.read_string_length(filename_ptr, filename_len);
	const file_t& file = m_file_contents.at(filename);

	// string preffix = "/lib/x86_64-linux-gnu/";
	// if (filename.substr(0, preffix.size()) == preffix)
		// filename = filename.replace(0, preffix.size(), "/usr/lib/debug/lib/x86_64-linux-gnu/");

	if (!m_libraries.count(filename)) {
		ElfParser elf(filename, file.data, file.length);
		elf.set_load_addr(load_addr);
		printf("Loaded library %s at 0x%lx (%lu symbols)\n", filename.c_str(),
		       elf.load_addr(), elf.symbols().size());
		m_libraries.insert({filename, move(elf)});
	}
}

void Vm::do_hc_end_run(RunEndReason reason, vaddr_t info_addr,
                       uint64_t instr_executed)
{
	set_instructions_executed(instr_executed);
	if (reason == RunEndReason::Crash)
		m_fault = m_mmu.read<FaultInfo>(info_addr);
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
			do_hc_get_mem_info(m_regs->rdi);
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
		case Hypercall::SubmitFilePointers:
			do_hc_submit_file_pointers(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case Hypercall::SubmitTimeoutPointers:
			do_hc_submit_timeout_pointers(m_regs->rdi, m_regs->rsi);
			break;
		case Hypercall::PrintStacktrace:
			do_hc_print_stacktrace(m_regs->rdi);
			break;
		case Hypercall::LoadLibrary:
			do_hc_load_library(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case Hypercall::EndRun:
			reason = (RunEndReason)m_regs->rdi;
			do_hc_end_run(reason, m_regs->rsi, m_regs->rdx);
			m_running = false;
			break;
		default:
			ASSERT(false, "unknown hypercall: %llu", m_regs->rax);
	}

	m_regs->rax = ret;
	set_regs_dirty();
}