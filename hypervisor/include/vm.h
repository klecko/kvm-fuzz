#ifndef _VM_H
#define _VM_H

#include <iostream>
#include <vector>
#include <unordered_map>
#include <sys/uio.h>
#include <libxdc.h>
#include "stats.h"
#include "mmu.h"
#include "common.h"
#include "kvm_aux.h"
#include "fault.h"

void init_kvm();

struct file_t {
	const void* data;
	size_t length;
	vaddr_t guest_buf;
};

class Vm {
public:
	enum RunEndReason {
		Exit,
		Breakpoint,
		Crash,
		Unknown = -1,
	};

	Vm(vsize_t mem_size, const std::string& kernelpath,
	   const std::string& filepath, const std::vector<std::string>& argv);

	// Copy constructor: creates a copy of `other` and allows using method reset
	Vm(const Vm& other);

	// Load kernel, run until it finishes initialization, and finally load user
	// elf. Then, we're ready to run
	void init();

	psize_t memsize() const;
	FaultInfo fault() const;

	// Reset Vm state to `other`, given that current Vm has been constructed
	// as a copy of `other`
	void reset(const Vm& other, Stats& stats);

	RunEndReason run(Stats& stats);

	void run_until(vaddr_t pc, Stats& stats);

	void set_breakpoint(vaddr_t addr);
	void remove_breakpoint(vaddr_t addr);

	// Associate `filename` with `content` to emulate file operations in the
	// guest. String `content` shouldn't be modified and it could be shared
	// by all threads. File content will be copied to kernel memory when kernel
	// submits a buffer, or immediately if it already submitted one.
	// If `check` is set, make sure a buffer was already provided so `content`
	// is immediately copied.
	void set_file(const std::string& filename, const std::string& content,
	              bool check = false);

	vaddr_t resolve_symbol(const std::string& symbol_name);

	void dump_regs();
	void dump_memory() const;
	void dump_memory(psize_t len) const;

private:
	static const size_t COVERAGE_BITMAP_SIZE = 0x10000;

	int m_vm_fd;
	int m_vcpu_fd;
	kvm_run*   m_vcpu_run;
#ifdef ENABLE_COVERAGE
	int m_vmx_pt_fd;
	uint8_t*   m_vmx_pt;
	void*      m_vmx_pt_bitmap;
	libxdc_t*  m_pt_decoder;
#endif
	kvm_regs*  m_regs;
	kvm_sregs* m_sregs;

	ElfParser  m_elf;
	ElfParser  m_kernel;
	ElfParser* m_interpreter;
	std::vector<std::string> m_argv;
	Mmu  m_mmu;
	bool m_running;
	std::unordered_map<vaddr_t, uint8_t> m_breakpoints_original_bytes;

	// Files contents indexed by filename. Kernel will synchronize with this
	// on startup
	std::unordered_map<std::string, file_t> m_file_contents;

	FaultInfo m_fault;

	int create_vm();
	void setup_vmx_pt();
	void setup_kvm();
	void load_elf();
	void load_kernel();
	void set_regs_dirty();
	void set_sregs_dirty();
	void* fetch_page(uint64_t page, bool* success);
	void get_coverage();
	void vm_err(const std::string& err);

	void handle_hypercall(RunEndReason&);
	vaddr_t do_hc_mmap(vaddr_t addr, vsize_t size, uint64_t page_flags, int flags);
	void do_hc_print(vaddr_t msg_addr);
	void do_hc_get_info(vaddr_t info_addr);
	vsize_t do_hc_get_file_len(size_t n);
	void do_hc_get_file_name(size_t n, vaddr_t buf_addr);
	void do_hc_set_file_buf(size_t n, vaddr_t buf_addr);
	void do_hc_fault(vaddr_t fault_info_addr);
	void do_hc_end_run();

	/* void handle_syscall();
	*/
};

#endif