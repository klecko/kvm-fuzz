#ifndef _VM_H
#define _VM_H

#include <vector>
#include <unordered_map>
#include <set>
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
	vaddr_t guest_data_addr;
	vaddr_t guest_length_addr;
};

class Vm {
public:
	enum RunEndReason {
		Exit,
		Debug,
		Crash,
		Unknown = -1,
	};

	struct Breakpoint {
		enum Type {
			RunEnd = 1 << 0,
			Coverage = 1 << 1,
			Hook = 1 << 2,
		};
		uint8_t type;
		uint8_t original_byte;
	};

	Vm(vsize_t mem_size, const std::string& kernel_path,
	   const std::string& binary_path, const std::vector<std::string>& argv,
	   const std::string& basic_blocks_path);

	// Copy constructor: creates a copy of `other` and allows using method reset
	Vm(const Vm& other);

	kvm_regs& regs();
	kvm_regs regs() const;
	Mmu& mmu();
	psize_t memsize() const;
	FaultInfo fault() const;
	uint64_t instructions_executed_last_run() const;

#ifdef ENABLE_COVERAGE_INTEL_PT
	uint8_t* coverage() const;
#endif
#ifdef ENABLE_COVERAGE_BREAKPOINTS
	const std::set<vaddr_t>& coverage() const;
#endif

	void reset_coverage();

	// Reset Vm state to `other`, given that current Vm has been constructed
	// as a copy of `other`
	void reset(const Vm& other, Stats& stats);

	void set_input(const std::string& input);

	RunEndReason run(Stats& stats);

	void run_until(vaddr_t pc, Stats& stats);

	void set_single_step(bool enabled);
	RunEndReason single_step(Stats& stats);

	void set_breakpoint(vaddr_t addr, Breakpoint::Type type);
	void remove_breakpoint(vaddr_t addr, Breakpoint::Type type);
	bool try_remove_breakpoint(vaddr_t addr, Breakpoint::Type type);
	void set_breakpoints_dirty(bool dirty);

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
	void dump(const std::string& filename);

private:
	int m_vm_fd;
	int m_vcpu_fd;
	kvm_run*   m_vcpu_run;
	kvm_regs*  m_regs;
	kvm_sregs* m_sregs;

#ifdef ENABLE_COVERAGE_INTEL_PT
	int m_vmx_pt_fd;
	uint8_t*   m_vmx_pt;
	uint8_t*   m_vmx_pt_bitmap;
	libxdc_t*  m_vmx_pt_decoder;
#endif

#ifdef ENABLE_COVERAGE_BREAKPOINTS
	std::set<vaddr_t> m_new_basic_block_hits;
#endif

	ElfParser  m_elf;
	ElfParser  m_kernel;
	ElfParser* m_interpreter;
	std::vector<std::string> m_argv;
	Mmu  m_mmu;
	bool m_running;

	// Breakpoints indexed by the address they are placed at
	std::unordered_map<vaddr_t, Breakpoint> m_breakpoints;

	// Whether setting or removing a breakpoint should dirty memory
	bool m_breakpoints_dirty;

	// Files contents indexed by filename. Kernel will synchronize with this
	// on startup
	std::unordered_map<std::string, file_t> m_file_contents;

	FaultInfo m_fault;

	// Instructions executed until last run and until previous run.
	// They are updated when guest uses hypercall EndRun or Fault.
	uint64_t m_instructions_executed;
	uint64_t m_instructions_executed_prev;

	// This is just for debugging
	std::vector<vaddr_t> m_allocations;

	int create_vm();
	void setup_kvm();
	void load_elfs();
#ifdef ENABLE_COVERAGE_INTEL_PT
	void setup_coverage();
	void update_coverage(Stats& stats);
#endif
#ifdef ENABLE_COVERAGE_BREAKPOINTS
	void setup_coverage(const std::string& path);
#endif
	void setup_kernel_execution();
	void set_regs_dirty();
	void set_sregs_dirty();
	void set_instructions_executed(uint64_t instr_executed);
	void* fetch_page(uint64_t page, bool* success);
	uint8_t set_breakpoint_to_memory(vaddr_t addr);
	void remove_breakpoint_from_memory(vaddr_t addr, uint8_t original_byte);
	void handle_breakpoint(RunEndReason& reason);
	void handle_hook();
	void print_instruction_pointer(int i, vaddr_t instruction_pointer);
	void print_stacktrace(const kvm_regs& regs, size_t num_frames=-1);
	void vm_err(const std::string& err);

	void handle_hypercall(RunEndReason&);
	vaddr_t do_hc_mmap(vaddr_t addr, vsize_t size, uint64_t page_flags, int flags);
	void do_hc_print(vaddr_t msg_addr);
	void do_hc_get_mem_info(vaddr_t mem_start_addr, vaddr_t mem_length_addr);
	vaddr_t do_hc_get_kernel_brk();
	void do_hc_get_info(vaddr_t info_addr);
	vsize_t do_hc_get_file_len(size_t n);
	void do_hc_get_file_name(size_t n, vaddr_t buf_addr);
	void do_hc_set_file_pointers(size_t n, vaddr_t buf_addr, vaddr_t length_addr);
	void do_hc_print_stacktrace(vaddr_t rsp, vaddr_t rip, vaddr_t rbp);
	void do_hc_fault(vaddr_t fault_info_addr, uint64_t instr_executed);
	void do_hc_end_run(uint64_t instructions_executed);

	/* void handle_syscall();
	*/
};

#endif