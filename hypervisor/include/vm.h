#ifndef _VM_H
#define _VM_H

#include <vector>
#include <unordered_map>
#include <set>
#include "stats.h"
#include "mmu.h"
#include "common.h"
#include "kvm_aux.h"
#include "fault.h"
#include "coverage.h"
#include "files.h"
#include "elfs.h"
#ifdef ENABLE_COVERAGE_INTEL_PT
#include <libxdc.h>
#endif

void init_kvm();

class Vm {
public:
	Vm(vsize_t mem_size, const std::string& kernel_path,
	   const std::string& binary_path, const std::vector<std::string>& argv);

	// Copy constructor: creates a copy of `other` and allows using method reset
	Vm(const Vm& other);

	kvm_regs& regs();
	kvm_regs regs() const;
	Mmu& mmu();
	ElfParser& elf();
	psize_t memsize() const;
	FaultInfo fault() const;
	uint64_t get_instructions_executed_and_reset();

	void setup_coverage();
	const Coverage& coverage() const;

	void reset_coverage();

	// Reset Vm state to `other`, given that current Vm has been constructed
	// as a copy of `other`
	void reset(const Vm& other, Stats& stats);

	// Keep this the same as in the kernel
	enum class RunEndReason : int {
		// Exit syscall
		Exit,
		// Breakpoint (type RunEnd)
		Breakpoint,
		// Debug event, such as single-step or hardware breakpoint
		Debug,
		// Crash, whose fault information can be obtained with `fault()`
		Crash,
		// Timeout
		Timeout,
		Unknown,
	};
	static const char* reason_str(RunEndReason reason);

	// Run the Vm
	RunEndReason run(Stats& stats);

	// Run the Vm until a given address
	void run_until(vaddr_t pc, Stats& stats);

	void set_single_step(bool enabled);
	RunEndReason single_step(Stats& stats);

	// Set and remove breakpoints. Execution will stop at given address, with
	// RunEndReason::Breakpoint.
	void set_breakpoint(vaddr_t addr);
	void remove_breakpoint(vaddr_t addr);

	// Set and remove hooks. They will be executed at given address.
	typedef void (*hook_handler_t)(Vm& vm);
	void set_hook(vaddr_t addr, hook_handler_t hook_handler);
	void remove_hook(vaddr_t addr);

	void set_breakpoints_dirty(bool dirty);

	enum class CheckCopied {
		Yes,
		No,
	};

	// Associate `filename` with `content` to emulate file operations in the
	// guest. This file will be shared by all the Vms. File content will be
	// copied to kernel memory when kernel submits a buffer, or immediately if
	// it already submitted one.  If `check` is set, it makes sure a buffer was
	// already provided so `content` is immediately copied.
	void set_shared_file(
		const std::string& filename,
		std::string content,
		CheckCopied check = CheckCopied::No
	);

	// Same as `set_shared_file`, but content is read from given filename.
	void read_and_set_shared_file(
		const std::string& filename,
		CheckCopied check = CheckCopied::No
	);

	// Same as `set_shared_file`, but the file is not shared by other Vms, and
	// `content` is a reference, so it isn't copied. Caller is responsible of
	// the referenced content and must take care of its lifetime.
	void set_file(
		const std::string& filename,
		FileRef content,
		CheckCopied check = CheckCopied::No
	);

	// Reset the timer inside the VM
	void reset_timer();

	// Set a timeout. If the timer inside the VM exceeds this value, run will
	// finish with RunEndReason::Timeout.
	void set_timeout(size_t microsecs);

	uint64_t read_msr(uint64_t msr);

	size_t stack_pop();
	void stack_push(size_t value);

	// Syscall tracing
	void set_tracing(bool tracing);
	void dump_trace(size_t id = 0);

	void print_current_stacktrace(size_t num_frames=-1);
	void print_stacktrace(const kvm_regs& regs, size_t num_frames=-1);
	void print_fault_info();

	void dump_regs();
	void dump_memory() const;
	void dump_memory(psize_t len) const;
	void dump(const std::string& filename);

private:
	struct Breakpoint {
		enum Type : uint8_t {
			RunEnd = 1 << 0,
			Coverage = 1 << 1,
			Hook = 1 << 2,
		};

		// This is an OR of one or more Types
		uint8_t type;

		// The original byte at memory, which we must reset when removing the
		// breakpoint.
		uint8_t original_byte;
	};

	int m_vm_fd;
	int m_vcpu_fd;
	kvm_run*   m_vcpu_run;
	kvm_regs*  m_regs;
	kvm_sregs* m_sregs;

#ifdef ENABLE_COVERAGE_INTEL_PT
	int        m_vmx_pt_fd;
	uint8_t*   m_vmx_pt;
	libxdc_t*  m_vmx_pt_decoder;
#endif

	static SharedFiles s_shared_files;
	static Elfs s_elfs;

	FileRefsByPath m_files;

	Coverage   m_coverage;

	Mmu  m_mmu;
	bool m_running;
	bool m_single_stepping;

	// Breakpoints indexed by the address they are placed at
	std::unordered_map<vaddr_t, Breakpoint> m_breakpoints;

	// Hook handlers indexed by address
	std::unordered_map<vaddr_t, hook_handler_t> m_hook_handlers;

	// Whether setting or removing a breakpoint should dirty memory
	bool m_breakpoints_dirty;

	FaultInfo m_fault;

	// Instructions executed until last run and until previous run.
	// They are updated when guest uses hypercall EndRun or Fault.
	uint64_t m_instructions_executed;
	uint64_t m_instructions_executed_prev;

	// Addresses of the timer and timeout value inside the VM. These are
	// submitted by the kernel using `hc_set_timeout_pointers`.
	vaddr_t m_timer_addr;
	vaddr_t m_timeout_addr;

	// Syscall tracing
	bool m_tracing;
	vaddr_t m_tracing_addr;
	struct {
		std::string name;
		uint64_t measure_start;
	} m_syscall;
	size_t m_next_trace_id;
	std::vector<std::pair<std::string, size_t>> m_trace;

	int create_vm();
	void setup_kvm();
	void load_elfs();
#ifdef ENABLE_COVERAGE_INTEL_PT
	void update_coverage(Stats& stats);
#endif
	void setup_kernel_execution(const std::vector<std::string>& argv);
	void set_regs_dirty();
	void set_sregs_dirty();
	void* fetch_page(uint64_t page, bool* success);
	void set_breakpoint(vaddr_t addr, Breakpoint::Type type);
	void remove_breakpoint(vaddr_t addr, Breakpoint::Type type);
	bool try_remove_breakpoint(vaddr_t addr, Breakpoint::Type type);
	uint8_t set_breakpoint_to_memory(vaddr_t addr);
	void remove_breakpoint_from_memory(vaddr_t addr, uint8_t original_byte);
	void handle_breakpoint(RunEndReason& reason);
	void maybe_write_file_to_guest(
		const std::string& filename,
		const GuestFile& file,
		CheckCopied check
	);
	std::pair<std::string, GuestFile> get_file_entry(size_t n);
	void vm_err(const std::string& err);

	void handle_hypercall(RunEndReason&);
	vaddr_t do_hc_mmap(vaddr_t addr, vsize_t size, uint64_t page_flags, int flags);
	void do_hc_print(vaddr_t msg_addr);
	void do_hc_get_mem_info(vaddr_t mem_info_addr);
	vaddr_t do_hc_get_kernel_brk();
	void do_hc_get_info(vaddr_t info_addr);
	void do_hc_get_file_info(size_t n, vaddr_t path_buf_addr, vaddr_t length_addr);
	void do_hc_submit_file_pointers(size_t n, vaddr_t buf_addr,
	                                vaddr_t length_addr);
	void do_hc_submit_timeout_pointers(vaddr_t timer_addr, vaddr_t timeout_addr);
	void do_hc_submit_tracing_pointer(vaddr_t tracing_addr);
	void do_hc_print_stacktrace(vaddr_t stacktrace_regs_addr);
	void do_hc_load_library(vaddr_t filename_ptr, vsize_t filename_len,
	                        vaddr_t load_addr);
	void do_hc_end_run(RunEndReason reason, vaddr_t info_addr);
	void do_hc_notify_syscall_start(vaddr_t syscall_name_addr, size_t measure_start);
	void do_hc_notify_syscall_end(size_t measure_end);

	/* void handle_syscall();
	*/
};

#endif