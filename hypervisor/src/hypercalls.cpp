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
	GetFileInfo,
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
	return s_elfs.kernel().initial_brk();
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
	ElfParser& elf = s_elfs.elf();
	ElfParser* interpreter = s_elfs.interpreter();
	ERROR_ON(!realpath(elf.path().c_str(), info.elf_path), "elf realpath");
	info.brk           = elf.initial_brk();
	info.num_files     = s_shared_files.size() + m_files.size();
	info.user_entry    = (interpreter ? interpreter->entry() : elf.entry());
	info.elf_entry     = elf.entry();
	info.elf_load_addr = elf.load_addr();
	info.interp_start  = (interpreter ? interpreter->load_addr() : 0);
	info.interp_end    = (interpreter ? info.interp_start + interpreter->size() : 0);
	info.phinfo        = elf.phinfo();

	// Make sure our struct termios corresponds to the one used by the kernel
	#if !defined(_HAVE_STRUCT_TERMIOS_C_ISPEED) ||   \
	    !defined(_HAVE_STRUCT_TERMIOS_C_OSPEED)
	#error struct termios in hypervisor doesn't have ispeed and ospeed?
	#endif
	tcgetattr(STDOUT_FILENO, &info.term);

	m_mmu.write(info_addr, info);
}

pair<string, GuestFile> Vm::get_file_entry(size_t n) {
	ASSERT(n < s_shared_files.size() + m_files.size(), "OOB n: %lu", n);
	if (n < s_shared_files.size())
		return s_shared_files.entry_at_pos(n);
	else
		return m_files.entry_at_pos(n - s_shared_files.size());
}

void Vm::do_hc_get_file_info(size_t n, vaddr_t path_buf_addr, vaddr_t length_addr) {
	auto file_entry = get_file_entry(n);
	FileRef file = file_entry.second.data;
	const string& path = file_entry.first;
	m_mmu.write_mem(path_buf_addr, path.c_str(), path.length() + 1);
	m_mmu.write<vsize_t>(length_addr, file.length);
}

void Vm::do_hc_submit_file_pointers(size_t n, vaddr_t data_addr,
                                    vaddr_t length_addr) {
	// Make sure ptrs weren't submitted yet
	auto file_entry = get_file_entry(n);
	GuestPtrs current_ptrs = file_entry.second.guest;
	ASSERT(current_ptrs.data_addr == 0 && current_ptrs.length_addr == 0,
	       "double submite_file_pointers for %s?", file_entry.first.c_str());

	// Submit given ptrs
	GuestPtrs ptrs = {
		.data_addr = data_addr,
		.length_addr = length_addr,
	};
	if (n < s_shared_files.size()) {
		s_shared_files.set_guest_ptrs_at_pos(n, ptrs);
	} else {
		m_files.set_guest_ptrs_at_pos(n - s_shared_files.size(), ptrs);
	}

	// Write the file data and length to given ptrs
	FileRef file = file_entry.second.data;
	m_mmu.write_mem(data_addr, file.ptr, file.length);
	m_mmu.write<vsize_t>(length_addr, file.length);
	dbgprintf("kernel set pointers for file '%s': 0x%lx 0x%lx\n",
	          file_entry.first.c_str(), data_addr, length_addr);
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
	// Kernel is telling us that the guest loader is mmaping a file.
	string filename = m_mmu.read_string_length(filename_ptr, filename_len);
	s_elfs.set_library_load_addr(filename, load_addr);
}

void Vm::do_hc_end_run(RunEndReason reason, vaddr_t info_addr) {
	if (reason == RunEndReason::Crash)
		m_fault = m_mmu.read<FaultInfo>(info_addr);
	m_running = false;
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
		case Hypercall::GetFileInfo:
			do_hc_get_file_info(m_regs->rdi, m_regs->rsi, m_regs->rdx);
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
			do_hc_end_run(reason, m_regs->rsi);
			break;
		default:
			ASSERT(false, "unknown hypercall: %llu", m_regs->rax);
	}

	m_regs->rax = ret;
	set_regs_dirty();
}