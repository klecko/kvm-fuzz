#ifndef _VM_H
#define _VM_H

#include <iostream>
#include <vector>
#include <unordered_map>
#include <sys/uio.h>
#include "stats.h"
#include "mmu.h"
#include "common.h"
#include "kvm_aux.h"

//#define COVERAGE

void init_kvm();

class Vm {
public:
	Vm(vsize_t mem_size, const std::string& kernelpath,
	   const std::string& filepath, const std::vector<std::string>& argv);

	// Copy constructor: creates a copy of `other` and allows using method reset
	Vm(const Vm& other);

	psize_t memsize() const;

	// Reset Vm state to `other`, given that current Vm has been constructed
	// as a copy of `other`
	void reset(const Vm& other, Stats& stats);

	void run(Stats& stats);

	void run_until(vaddr_t pc, Stats& stats);

	void set_breakpoint(vaddr_t addr);
	void remove_breakpoint(vaddr_t addr);

	// Associate `filename` with `content` to emulate file operations in the
	// guest. String `content` shouldn't be modified and it could be shared
	// by all threads
	void set_file(const std::string& filename, const std::string& content);

	void dump_regs();
	void dump_memory() const;
	void dump_memory(psize_t len) const;

private:
	int m_vm_fd;
	int m_vcpu_fd;
	struct kvm_run* m_vcpu_run;
	int m_vmx_pt_fd;
	uint8_t*   m_vmx_pt;
	kvm_regs*  m_regs;
	kvm_sregs* m_sregs;
	ElfParser  m_elf;
	ElfParser  m_kernel;
	ElfParser* m_interpreter;
	Mmu  m_mmu;
	bool m_running;
	std::unordered_map<vaddr_t, uint8_t> m_breakpoints_original_bytes;

	// Files contents indexed by filename. Kernel will synchronize with this
	// on startup
	std::unordered_map<std::string, struct iovec> m_file_contents;

	void setup_kvm();
	void load_elf(const std::vector<std::string>& argv);
	void load_kernel();
	void set_regs_dirty();
	void set_sregs_dirty();
	void get_coverage();
	void vm_err(const std::string& err);

	void handle_hypercall();
	vaddr_t do_hc_mmap(vaddr_t addr, vsize_t size, uint64_t page_flags, int flags);
	void do_hc_print(vaddr_t msg_addr);
	void do_hc_get_info(vaddr_t info_addr);
	void do_hc_end_run();

	/* void handle_syscall();
	*/
};

#endif