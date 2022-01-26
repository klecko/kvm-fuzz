#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <sys/mman.h>
#include <cstring>
#include "vm.h"
#include "utils.h"

using namespace std;

int g_kvm_fd = -1;
const char* Vm::reason_str[] = {"Exit", "Debug", "Crash", "Timeout", "Unknown"};

__attribute__((constructor))
void init_kvm() {
	g_kvm_fd = open("/dev/kvm", O_RDWR);
	ERROR_ON(g_kvm_fd == -1, "open /dev/kvm");

	int api_ver = ioctl(g_kvm_fd, KVM_GET_API_VERSION, 0);
	ASSERT(api_ver == KVM_API_VERSION, "kvm api version doesn't match: %d vs %d",
	       KVM_API_VERSION, api_ver);

#ifdef ENABLE_COVERAGE_INTEL_PT
	int vmx_pt = ioctl(g_kvm_fd, KVM_VMX_PT_SUPPORTED);
	ASSERT(vmx_pt != -1, "vmx_pt is not loaded");
	ASSERT(vmx_pt != -2, "Intel PT is not supported on this CPU");
#endif
}

SharedFiles Vm::s_shared_files;
Elfs Vm::s_elfs;

Vm::Vm(vsize_t mem_size, const string& kernel_path, const string& binary_path,
       const vector<string>& argv)
	: m_vm_fd(create_vm())
	, m_mmu(m_vm_fd, m_vcpu_fd, mem_size)
	, m_running(false)
	, m_breakpoints_dirty(false)
	, m_instructions_executed(0)
	, m_instructions_executed_prev(0)
	, m_timer_addr(0)
	, m_timeout_addr(0)
{
	s_elfs.init(binary_path, kernel_path);
	load_elfs();
	setup_kvm();
	setup_kernel_execution(argv);
	printf("Ready to run!\n");
}

Vm::Vm(const Vm& other)
	: m_vm_fd(create_vm())
	, m_files(other.m_files)
	, m_mmu(m_vm_fd, m_vcpu_fd, other.m_mmu)
	, m_running(false)
	, m_breakpoints(other.m_breakpoints)
	, m_hook_handlers(other.m_hook_handlers)
	, m_breakpoints_dirty(other.m_breakpoints_dirty)
	, m_instructions_executed(other.m_instructions_executed)
	, m_instructions_executed_prev(other.m_instructions_executed_prev)
	, m_timer_addr(other.m_timer_addr)
	, m_timeout_addr(other.m_timeout_addr)
{
	// Elfs are already relocated by the other VM, we can init vmx pt
#ifdef ENABLE_COVERAGE_INTEL_PT
	setup_coverage();
#endif

	setup_kvm();

	// Copy registers
	memcpy(m_regs, other.m_regs, sizeof(*m_regs));

	// Copy sregs
	memcpy(m_sregs, other.m_sregs, sizeof(*m_sregs));

	// Copy MSRs
	size_t sz = sizeof(kvm_msrs) + sizeof(kvm_msr_entry)*8;
	kvm_msrs* msrs = (kvm_msrs*)alloca(sz);
	memset(msrs, 0, sz);
	msrs->nmsrs = 8;
	msrs->entries[0].index = MSR_LSTAR;
	msrs->entries[1].index = MSR_STAR;
	msrs->entries[2].index = MSR_SYSCALL_MASK;
	msrs->entries[3].index = MSR_FS_BASE;
	msrs->entries[4].index = MSR_GS_BASE;
	msrs->entries[5].index = MSR_FIXED_CTR_CTRL;
	msrs->entries[6].index = MSR_PERF_GLOBAL_CTRL;
	msrs->entries[7].index = MSR_FIXED_CTR0;
	ioctl_chk(other.m_vcpu_fd, KVM_GET_MSRS, msrs);
	ioctl_chk(m_vcpu_fd, KVM_SET_MSRS, msrs);

	// Copy Local APIC
	kvm_lapic_state lapic;
	ioctl_chk(other.m_vcpu_fd, KVM_GET_LAPIC, &lapic);
	ioctl_chk(m_vcpu_fd, KVM_SET_LAPIC, &lapic);

	// Indicate we have dirtied registers
	set_regs_dirty();
	set_sregs_dirty();
}

int Vm::create_vm() {
	m_vm_fd = ioctl_chk(g_kvm_fd, KVM_CREATE_VM, 0);

	struct kvm_pit_config pit = {
		.flags = KVM_PIT_SPEAKER_DUMMY,
	};
	ioctl_chk(m_vm_fd, KVM_CREATE_IRQCHIP, 0);
	ioctl_chk(m_vm_fd, KVM_CREATE_PIT2, &pit);

#ifdef ENABLE_KVM_DIRTY_LOG_RING
	size_t max_size = ioctl_chk(m_vm_fd, KVM_CHECK_EXTENSION, KVM_CAP_DIRTY_LOG_RING);
	ASSERT(max_size, "kvm dirty log ring not available");

	kvm_enable_cap cap = {
		.cap = KVM_CAP_DIRTY_LOG_RING,
		.args = {max_size}
	};
	ioctl_chk(m_vm_fd, KVM_ENABLE_CAP, &cap);
#endif

	m_vcpu_fd = ioctl_chk(m_vm_fd, KVM_CREATE_VCPU, 0);

	size_t vcpu_run_size = ioctl_chk(g_kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	m_vcpu_run = (kvm_run*)mmap(nullptr, vcpu_run_size, PROT_READ|PROT_WRITE,
	                            MAP_SHARED, m_vcpu_fd, 0);
	ERROR_ON(m_vcpu_run == MAP_FAILED, "mmap vcpu_run");

	m_regs  = &m_vcpu_run->s.regs.regs;
	m_sregs = &m_vcpu_run->s.regs.sregs;

#ifdef ENABLE_COVERAGE_INTEL_PT
	m_vmx_pt_fd      = 0;
	m_vmx_pt         = nullptr;
	m_vmx_pt_decoder = nullptr;
#endif
	return m_vm_fd;
}

void Vm::setup_kvm() {
	ioctl_chk(m_vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000);

	// Set special registers for long mode
	kvm_sregs sregs;
	ioctl_chk(m_vcpu_fd, KVM_GET_SREGS, &sregs);
	sregs.cr3  = Mmu::PAGE_TABLE_PADDR;
	sregs.cr4  = CR4_PAE | CR4_OSXMMEXCPT | CR4_OSFXSR | CR4_OSXSAVE;
	sregs.cr0  = CR0_PE | CR0_MP | CR0_ET| CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.efer = EFER_NXE | EFER_LME | EFER_LMA | EFER_SCE;

	// Setup dummy segments. This is needed so we start directly in long mode.
	// However, this doesn't set the GDT. It will be properly set by the kernel
	// inside the VM.
	kvm_segment seg = {
		.base     = 0,          // base address
		.limit    = 0xffffffff, // limit
		.selector = 0x8,        // index 1 (index 0 is nullptr segment descriptor)
		.type     = 11,         // read, execute, accessed
		.present  = 1,          // bit P
		.dpl      = 0,          // Descriptor Privilege Level. 0 for kernel
		.db       = 0,          // Default operand size / Big
		.s        = 1,          // Descriptor type
		.l        = 1,          // Long: 64-bit segment. db must be zero
		.g        = 1           // Granularity: needs to be 1 here
	};
	sregs.cs = seg;
	seg.type     = 3;    // write, accessed
	seg.selector = 0x10; // index 2
	sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg;
	ioctl_chk(m_vcpu_fd, KVM_SET_SREGS, &sregs);

	// Setup cpuid
	size_t sz = sizeof(kvm_cpuid2) + sizeof(kvm_cpuid_entry2)*100;
	kvm_cpuid2* cpuid = (kvm_cpuid2*)alloca(sz);
	memset(cpuid, 0, sz);
	cpuid->nent = 100;
	ioctl_chk(g_kvm_fd, KVM_GET_SUPPORTED_CPUID, cpuid);
	ioctl_chk(m_vcpu_fd, KVM_SET_CPUID2, cpuid);

	// Setup xcr0 (extended control register)
	kvm_xcrs xcrs;
	ioctl_chk(m_vcpu_fd, KVM_GET_XCRS, &xcrs);
	ASSERT(xcrs.nr_xcrs >= 1, "0 xcrs");
	ASSERT(xcrs.xcrs[0].xcr == 0, "first xcr is %x", xcrs.xcrs[0].xcr);
	xcrs.xcrs[0].value |= XCR0_X87 | XCR0_SSE | XCR0_AVX;
	ioctl_chk(m_vcpu_fd, KVM_SET_XCRS, &xcrs);

	// Set debug
	set_single_step(false);

	// Set register sync
	m_vcpu_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS;
}

#if defined(ENABLE_COVERAGE_INTEL_PT)
typedef void* (*page_fetcher_t)(void*, uint64_t, bool*);
typedef void  (*bb_callback_t)(void*, uint64_t, uint64_t);
typedef void  (*edge_callback_t)(void*, uint64_t, uint64_t);

template<typename M>
inline page_fetcher_t cast_page_fetcher(M ptr) {
	// Make clang happy
	return *reinterpret_cast<page_fetcher_t*>(&ptr);
}

void Vm::setup_coverage() {
	// Get coverage range. Elf should have been loaded by now
	auto limits = m_elf.section_limits(".text");
	vmx_pt_filter_iprs filter0 = { limits.first, limits.second };
	printf_once("Coverage range: 0x%llx to 0x%llx\n", filter0.a, filter0.b);

	// VMX PT
	m_vmx_pt_fd = ioctl_chk(m_vcpu_fd, KVM_VMX_PT_SETUP_FD, 0);
	size_t vmx_pt_size = ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, 0);
	m_vmx_pt = (uint8_t*)mmap(nullptr, vmx_pt_size, PROT_READ|PROT_WRITE,
	                          MAP_SHARED, m_vmx_pt_fd, 0);
	ERROR_ON(m_vmx_pt == MAP_FAILED, "mmap vmx_pt");

	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_CONFIGURE_ADDR0, &filter0);
	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_ENABLE_ADDR0, 0);
	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_ENABLE, 0);

	// libxdc
	uint64_t filter[4][2] = {0};
	filter[0][0] = filter0.a;
	filter[0][1] = filter0.b;
	void* bitmap = m_coverage.bitmap();
	m_vmx_pt_decoder = libxdc_init(filter, cast_page_fetcher(&Vm::fetch_page),
	                               this, bitmap, COVERAGE_BITMAP_SIZE);
	//libxdc_register_bb_callback(decoder, (bb_callback_t)test_bb, nullptr);
	//libxdc_register_edge_callback(decoder, (edge_callback_t)test_edge, nullptr);
	//libxdc_enable_tracing(decoder);
}

#elif defined(ENABLE_COVERAGE_BREAKPOINTS)
void Vm::setup_coverage(const string& path) {
	ifstream bbs(path);
	if (!bbs.good()) {
		ElfParser& elf = s_elfs.elf();
		// Command injection woopsie doopsie
		printf("Basic blocks file '%s' doesn't exist. It will be created using "
		       "angr. This can take some minutes.\n", path.c_str());
		string cmd = "./scripts/generate_basic_blocks.py " + elf.path() +
		             " " + path + " " + to_hex(elf.load_addr());
		ERROR_ON(system(cmd.c_str()) != 0, "failed to run cmd %s", cmd.c_str());
		bbs.open(path);
	}
	ERROR_ON(!bbs.good(), "opening basic blocks file %s", path.c_str());
	size_t count = 0;
	vaddr_t bb;
	bbs >> hex >> bb;
	while (bbs.good()) {
		set_breakpoint(bb, Breakpoint::Type::Coverage);
		bbs >> bb;
		count++;
	}
	bbs.close();
	ASSERT(count > 0, "no basic block read from %s", path.c_str());
	printf("Read %lu basic blocks from %s\n", count, path.c_str());
}
#endif


void Vm::load_elfs() {
	// First, the kernel
	const ElfParser& kernel = s_elfs.kernel();
	dbgprintf("Loading kernel at 0x%lx\n", kernel.load_addr());
	m_mmu.load_elf(kernel.segments(), ElfType::Kernel);

	// Now, user elf. Assign load address if it's DYN (PIE) and load it
	ElfParser& elf = s_elfs.elf();
	if (elf.type() == ET_DYN)
		elf.set_load_addr(Mmu::ELF_ADDR);
	dbgprintf("Loading elf at 0x%lx\n", elf.load_addr());
	m_mmu.load_elf(elf.segments(), ElfType::User);

	// If user elf has interpreter, assign load address and load it
	ElfParser* interpreter = s_elfs.interpreter();
	if (interpreter) {
		interpreter->set_load_addr(Mmu::INTERPRETER_ADDR);
		dbgprintf("Loading interpreter %s at 0x%lx\n",
		          interpreter->path().c_str(), interpreter->load_addr());
		m_mmu.load_elf(interpreter->segments(), ElfType::User);
	}

	// Set elf dependencies as memory-loaded files, and add them to the list
	// of libraries. ElfParsers are created from the data located in s_shared_files.
	for (const string& library_path : elf.get_dependencies()) {
		GuestFile file = s_shared_files.set_file(library_path);
		s_elfs.add_library(library_path, file.data);
	}
}

void Vm::setup_kernel_execution(const vector<string>& argv) {
	m_regs->rsp = m_mmu.alloc_kernel_stack();
	m_regs->rflags = 2; // TODO: what about IOPL
	m_regs->rip = s_elfs.kernel().entry();

	// Let's write argv to kernel stack, so he can then write it to user stack
	// Write argv strings saving pointers to each arg
	vector<vaddr_t> argv_addrs;
	for (const string& arg : argv) {
		m_regs->rsp -= arg.size() + 1;
		m_mmu.write_mem(m_regs->rsp, arg.c_str(), arg.size()+1);
		argv_addrs.push_back(m_regs->rsp);
	}
	argv_addrs.push_back(0); // nullptr ptr, end of argv

	// Align rsp
	m_regs->rsp &= ~0x7;

	// Set up argv
	for (auto it = argv_addrs.rbegin(); it != argv_addrs.rend(); ++it) {
		m_regs->rsp -= 8;
		m_mmu.write<vaddr_t>(m_regs->rsp, *it);
	}

	// Setup args for kmain
	m_regs->rdi = argv.size(); // argc
	m_regs->rsi = m_regs->rsp; // argv
	set_regs_dirty();
}

void Vm::set_regs_dirty() {
	m_vcpu_run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
}

void Vm::set_sregs_dirty() {
	m_vcpu_run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
}

void Vm::set_instructions_executed(uint64_t instr_executed) {
	m_instructions_executed_prev = m_instructions_executed;
	m_instructions_executed = instr_executed;
}

kvm_regs& Vm::regs() {
	return *m_regs;
}

kvm_regs Vm::regs() const {
	return *m_regs;
}

Mmu& Vm::mmu() {
	return m_mmu;
}

ElfParser& Vm::elf() {
	return s_elfs.elf();
}

psize_t Vm::memsize() const {
	return m_mmu.size();
}

FaultInfo Vm::fault() const {
	return m_fault;
}

uint64_t Vm::instructions_executed_last_run() const {
	// Since we are not resetting guest MSRs, these counters are not resetted
	// each run.
	return m_instructions_executed - m_instructions_executed_prev;
}

const Coverage& Vm::coverage() const {
	return m_coverage;
}

void Vm::reset_coverage() {
	m_coverage.reset();
}

void Vm::reset(const Vm& other, Stats& stats) {
	// Reset mmu, regs and sregs
	stats.reset_pages += m_mmu.reset(other.m_mmu);
	memcpy(m_regs, other.m_regs, sizeof(*m_regs));
	memcpy(m_sregs, other.m_sregs, sizeof(*m_sregs));

	// Reset MSRs
	// We're not doing this for now because it's too expensive, and everything
	// seems to work fine. But beware guest is usually setting MSR_FS_BASE
	// and MSR_GS_BASE with syscall arch_prctl.
	// size_t sz = sizeof(kvm_msrs) + sizeof(kvm_msr_entry)*8;
	// kvm_msrs* msrs = (kvm_msrs*)alloca(sz);
	// msrs->nmsrs = 8;
	// msrs->entries[0].index = MSR_LSTAR;
	// msrs->entries[1].index = MSR_STAR;
	// msrs->entries[2].index = MSR_SYSCALL_MASK;
	// msrs->entries[3].index = MSR_FS_BASE;
	// msrs->entries[4].index = MSR_GS_BASE;
	// msrs->entries[5].index = MSR_FIXED_CTR_CTRL;
	// msrs->entries[6].index = MSR_PERF_GLOBAL_CTRL;
	// msrs->entries[7].index = MSR_FIXED_CTR0;
	// ioctl_chk(other.m_vcpu_fd, KVM_GET_MSRS, msrs);
	// ioctl_chk(m_vcpu_fd, KVM_SET_MSRS, msrs);

	// Reset LAPIC. This is also expensive. Let's just not reset it and hope
	// everything is okay :')
	// kvm_lapic_state lapic;
	// ioctl_chk(other.m_vcpu_fd, KVM_GET_LAPIC, &lapic);
	// ioctl_chk(m_vcpu_fd, KVM_SET_LAPIC, &lapic);

	// Indicate we have dirtied registers
	set_regs_dirty();
	set_sregs_dirty();
}

void Vm::set_input(FileRef input) {
	// Set input as a file which the guest will open and read, making sure
	// the kernel has already submitted a buffer so the input is copied to its
	// memory.
	set_file("input", input, CheckCopied::Yes);

	// If our target received the input in a buffer instead of using open and
	// read, we may want to write it to the guest memory, instead of using
	// memory-loaded files.
	// Assuming rdi is buffer pointer, rsi is input length and rdx is
	// buffer length:
	// size_t input_size = min((size_t)m_regs->rdx, input.size());
	// m_mmu.write_mem(m_regs->rdi, input.c_str(), input_size);
	// m_regs->rsi = input_size;
}

Vm::RunEndReason Vm::run(Stats& stats) {
	cycle_t cycles;
	RunEndReason reason = RunEndReason::Unknown;
	m_running = true;

	while (m_running) {
		cycles = rdtsc2();
		ioctl_chk(m_vcpu_fd, KVM_RUN, 0);
		stats.kvm_cycles += rdtsc2() - cycles;
		stats.vm_exits++;
		switch (m_vcpu_run->exit_reason) {
			case KVM_EXIT_HLT:
				vm_err("HLT");
				break;

			case KVM_EXIT_IO:
				if (m_vcpu_run->io.direction == KVM_EXIT_IO_OUT &&
					m_vcpu_run->io.port == 16)
				{
					// This will change `reason` in case it sets `m_running`
					// to false
					cycles = rdtsc2();
					handle_hypercall(reason);
					stats.hypercall_cycles += rdtsc2() - cycles;
					stats.vm_exits_hc++;
				} else {
					vm_err("IO");
				}
				break;

			case KVM_EXIT_DEBUG:
				/* printf("breakpoint hit\n");
				dump_regs();
				m_regs->rip += 1;
				set_regs_dirty();
				cout << endl;
				break; */
				stats.vm_exits_debug++;
				if (m_breakpoints.count(m_regs->rip))
					handle_breakpoint(reason);
				else {
					reason = RunEndReason::Debug;
					m_running = false;
				}
				break;

#ifdef ENABLE_COVERAGE_INTEL_PT
			case KVM_EXIT_VMX_PT_TOPA_MAIN_FULL:
				stats.vm_exits_cov++;
				update_coverage(stats);
				break;
#endif

			case KVM_EXIT_FAIL_ENTRY:
				vm_err("KVM_EXIT_FAIL_ENTRY");
				break;

			case KVM_EXIT_INTERNAL_ERROR:
				vm_err("KVM_EXIT_INTERNAL_ERROR");
				break;

			case KVM_EXIT_SHUTDOWN:
				vm_err("KVM_EXIT_SHUTDOWN");
				break;

			default:
				vm_err("UNKNOWN EXIT " + to_string(m_vcpu_run->exit_reason));
		}
	}

#ifdef ENABLE_COVERAGE_INTEL_PT
	// Before returning, update coverage if VMX PT has been initialised
	if (m_vmx_pt) {
		update_coverage(stats);
	}
#endif

	return reason;
}

void Vm::handle_breakpoint(RunEndReason& reason) {
	vaddr_t addr = m_regs->rip;
	ASSERT(m_breakpoints.count(addr), "not existing breakpoint: 0x%lx", addr);

	Breakpoint& bp = m_breakpoints[addr];

	// If it's of type RunEnd, stop running and stop handling the breakpoint
	if (bp.type & Breakpoint::RunEnd) {
		reason = RunEndReason::Debug;
		m_running = false;
		return;
	}

	// If it's a hook handle it, then remove breakpoint, single step and set
	// breakpoint again
	if (bp.type & Breakpoint::Type::Hook) {
		hook_handler_t hook_handler = m_hook_handlers[addr];
		ASSERT(hook_handler, "hook breakpoint without hook handler at 0x%lx", addr);
		hook_handler(*this);
		remove_breakpoint(addr, Breakpoint::Hook);
		Stats dummy;
		RunEndReason reason = single_step(dummy);
		ASSERT(reason == RunEndReason::Debug, "run end reason: %s", reason_str[reason]);
		set_breakpoint(addr, Breakpoint::Hook);

		// single_step sets m_running to false. Set it to true again
		m_running = true;
	}

#ifdef ENABLE_COVERAGE_BREAKPOINTS
	// If it's a coverage breakpoint, add address to basic block hits and
	// remove it
	if (bp.type & Breakpoint::Type::Coverage) {
		remove_breakpoint(addr, Breakpoint::Coverage);
		m_coverage.add(addr);
	}
#endif

}

void Vm::run_until(vaddr_t pc, Stats& stats) {
	set_breakpoint(pc, Breakpoint::Type::RunEnd);
	RunEndReason reason = run(stats);
	remove_breakpoint(pc, Breakpoint::Type::RunEnd);

	if (reason == RunEndReason::Crash)
		print_fault_info();
	ASSERT(reason == RunEndReason::Debug, "run until end reason: %s",
	       Vm::reason_str[reason]);
	ASSERT(m_regs->rip == pc, "run until stopped at 0x%llx instead of 0x%lx",
	       m_regs->rip, pc);
}

void Vm::set_single_step(bool enabled) {
	kvm_guest_debug debug;
	memset(&debug, 0, sizeof(debug));
	debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP |
	                KVM_GUESTDBG_USE_SW_BP;
	if (enabled)
		debug.control |= KVM_GUESTDBG_SINGLESTEP;
	ioctl_chk(m_vcpu_fd, KVM_SET_GUEST_DEBUG, &debug);
}

Vm::RunEndReason Vm::single_step(Stats& stats) {
	set_single_step(true);
	RunEndReason reason = run(stats);
	set_single_step(false);
	return reason;
}

#ifdef ENABLE_COVERAGE_INTEL_PT
void* Vm::fetch_page(uint64_t page, bool* success) {
	thread_local unordered_map<uint64_t, void*> cache;
	thread_local uint64_t last_page = 0;
	thread_local void* last_result = nullptr;
	page &= PTL1_MASK;
	//printf("fetching 0x%lx\n", page);

	*success = true;

	// If it's the last page fetched, just return the last result
	if (page == last_page)
		return last_result;

	// If it's in the cache, get the result from there. Otherwise, get it and
	// update the cache.
	last_page = page;
	if (cache.count(page))
		last_result = cache[page];
	else {
		last_result = m_mmu.get(page);
		cache[page] = last_result;
	}

	return last_result;
}

void test_bb(void*, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
	printf("bb callback: %lx %lx %lx\n", arg1, arg2, arg3);
}

void test_edge(void*, uint64_t arg1, uint64_t arg2) {
	printf("edge callback: %lx %lx\n", arg1, arg2);
}

void Vm::update_coverage(Stats& stats) {
	cycle_t cycles = rdtsc2();
	size_t size = ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, 0);

	if (size) {
		/* uint8_t* buf = (uint8_t*)malloc(size+1);
		memcpy(buf, m_vmx_pt, size);
		buf[size] = 0x55; */

		// KVM-PT was modified to allow this, because I thought the memcpy was
		// very expensive, but it seems it isn't
		m_vmx_pt[size] = 0x55;

		decoder_result_t ret = libxdc_decode(m_vmx_pt_decoder, m_vmx_pt, size);
		ASSERT(ret == decoder_result_t::decoder_success, "libxdc decode: %d", ret);

		// ofstream ofs("libtiff-trace");
		// assert(ofs.good());
		// ofs.write((char*)m_vmx_pt, size);
		// assert(ofs.good());
		// ofs.close();
		// printf("IPT data dumped. Bitmap hash: 0x%lx\n",
		//        libxdc_bitmap_get_hash(m_vmx_pt_decoder));
		// auto limits = m_elf.section_limits(".text");
		// printf("Limits: 0x%lx, 0x%lx\n", limits.first, limits.second);

		//free(buf);
	}
	stats.update_cov_cycles += rdtsc2() - cycles;
}
#endif

uint8_t Vm::set_breakpoint_to_memory(vaddr_t addr) {
	uint8_t val;
	if (m_breakpoints_dirty) {
		val = m_mmu.read<uint8_t>(addr);
		m_mmu.write<uint8_t>(addr, 0xCC, CheckPerms::No);
	} else {
		uint8_t* p = m_mmu.get(addr);
		val = *p;
		*p = 0xCC;
	}
	ASSERT(val != 0xCC, "setting breakpoint twice at 0x%lx", addr);
	return val;
}

void Vm::remove_breakpoint_from_memory(vaddr_t addr, uint8_t original_byte) {
	uint8_t val;
	if (m_breakpoints_dirty) {
		val = m_mmu.read<uint8_t>(addr);
		m_mmu.write<uint8_t>(addr, original_byte, CheckPerms::No);
	} else {
		uint8_t* p = m_mmu.get(addr);
		val = *p;
		*p = original_byte;
	}
	ASSERT(val == 0xCC, "not set breakpoint at 0x%lx", addr);
}

void Vm::set_breakpoint(vaddr_t addr, Breakpoint::Type type) {
	if (!m_breakpoints.count(addr)) {
		// Create breakpoint
		m_breakpoints[addr] = {
			.type = type,
			.original_byte = set_breakpoint_to_memory(addr),
		};
	} else {
		// If breakpoint type exists but its type is only Coverage, maybe the
		// breakpoint is not in memory. Write it just in case.
		Breakpoint& bp = m_breakpoints[addr];
		if (bp.type == Breakpoint::Coverage)
			*m_mmu.get(addr) = 0xCC;

		// Add type to breakpoint
		ASSERT((bp.type & type) == 0, "set breakpoint twice at 0x%lx, type %d\n",
		       addr, type);
		bp.type |= type;
	}
}

void Vm::remove_breakpoint(vaddr_t addr, Breakpoint::Type type) {
	bool removed = try_remove_breakpoint(addr, type);
	ASSERT(removed, "not existing breakpoint at 0x%lx, type %d", addr, type);
}

bool Vm::try_remove_breakpoint(vaddr_t addr, Breakpoint::Type type) {
	if (!m_breakpoints.count(addr))
		return false;
	Breakpoint& bp = m_breakpoints[addr];
	if (!(bp.type & type))
		return false;

	// Special case for coverage: just remove it from memory if it's the only
	// type left. We never remove coverage breakpoints from m_breakpoints.
	// This is because the original VM we forked from has the breakpoints set
	// in its memory. Removing the breakpoint from our memory doesn't dirty
	// memory, so it isn't resetted, but guest could write to that memory and
	// dirty it. In that case the breakpoint will appear again in memory when
	// it's resetted, so we have to keep it in m_breakpoints to handle it.
	if (type == Breakpoint::Type::Coverage) {
		if (bp.type == type)
			remove_breakpoint_from_memory(addr, bp.original_byte);
		return true;
	}
	// if (type == Breakpoint::Type::Coverage && bp.type == type) {
	// 	remove_breakpoint_from_memory(addr, bp.original_byte);
	// 	return true;
	// }

	bp.type &= ~type;

	if (bp.type == 0) {
		// Actually remove breakpoint from memory
		remove_breakpoint_from_memory(addr, bp.original_byte);
		m_breakpoints.erase(addr);
	}
	return true;
}

void Vm::set_hook(vaddr_t addr, hook_handler_t hook_handler) {
	ASSERT(!m_hook_handlers.count(addr), "hook handler for 0x%lx already exists", addr);
	set_breakpoint(addr, Breakpoint::Type::Hook);
	m_hook_handlers[addr] = hook_handler;
}

void Vm::remove_hook(vaddr_t addr) {
	ASSERT(m_hook_handlers.count(addr), "hook handler for 0x%lx doesn't exist", addr);
	remove_breakpoint(addr, Breakpoint::Type::Hook);
	m_hook_handlers.erase(addr);
}

void Vm::set_breakpoints_dirty(bool dirty) {
	m_breakpoints_dirty = dirty;
}

void Vm::read_and_set_shared_file(const string& filename, CheckCopied check) {
	set_shared_file(filename, read_file(filename), check);
}

void Vm::set_shared_file(const string& filename, string content, CheckCopied check) {
	GuestFile file = s_shared_files.set_file(filename, move(content));
	maybe_write_file_to_guest(filename, file, check);
}

void Vm::set_file(const string& filename, FileRef content, CheckCopied check) {
	GuestFile file = m_files.set_file(filename, content);
	maybe_write_file_to_guest(filename, file, check);
}

void Vm::maybe_write_file_to_guest(
	const string& filename,
	const GuestFile& file,
	CheckCopied check
) {
	if (file.guest.data_addr) {
		// File already existed and kernel submitted its pointers. Write file
		// data and length into kernel memory. Note this should be done before
		// guest opens the file.
		m_mmu.write_mem(file.guest.data_addr, file.data.ptr, file.data.length);
		m_mmu.write<vaddr_t>(file.guest.length_addr, file.data.length);
	} else {
		// File didn't exist or kernel didn't submit its pointers with
		// hc_set_file_pointers yet.
		ASSERT(!(check == CheckCopied::Yes), "kernel didn't submit ptrs for "
		      "file '%s'", filename.c_str());
	}
}

void Vm::reset_timer() {
	ASSERT(m_timer_addr, "trying to reset timer but kernel didn't submit ptr");
	m_mmu.write<vsize_t>(m_timer_addr, 0);
}

void Vm::set_timeout(size_t microsecs) {
	ASSERT(m_timeout_addr, "trying to set timeout but kernel didnt submit ptr");
	m_mmu.write<vsize_t>(m_timeout_addr, microsecs);
}

void print_stacktrace_line(const ElfParser& elf, size_t i, vaddr_t pc) {
	// PC is the return address, which means it points to the instruction after
	// the 'call' instruction. We substract 1 to that PC to get the symbol and
	// source information of the 'call' instruction and not the instruction
	// after it. However, we want to print the actual PC and the actual offset
	// within the symbol.
	symbol_t symbol;
	bool have_symbol = elf.addr_to_symbol(pc - 1, symbol);
	string source = elf.addr_to_source(pc - 1);

	printf("#%lu 0x%016lx", i, pc);
	if (have_symbol) {
		size_t offset = pc - symbol.value;
		printf(" %s + 0x%lx", symbol.name.c_str(), offset);
	}
	if (!source.empty())
		printf(" at %s", source.c_str());
	else
		printf(" from %s", elf.path().c_str());
	printf("\n");
}

void Vm::print_current_stacktrace(size_t num_frames) {
	print_stacktrace(regs(), num_frames);
}

void Vm::print_stacktrace(const kvm_regs& kregs, size_t num_frames){
	// List of all the elfs
	std::vector<const ElfParser*> elfs = s_elfs.all_elfs();

	// Get and print the stacktrace
	vector<pair<vaddr_t, const ElfParser*>> stacktrace =
		ElfParser::get_stacktrace(elfs, kregs, num_frames, m_mmu);
	for (size_t i = 0; i < stacktrace.size(); i++) {
		vaddr_t pc = stacktrace[i].first;
		const ElfParser& elf = *stacktrace[i].second;
		print_stacktrace_line(elf, i, pc);
	}

	if (stacktrace.size() <= 1) {
		printf("(no stacktrace available)\n\n");
		printf("trying to dump stack instead\n");
		for (size_t i = 0; i < 16; i++) {
			size_t value = m_mmu.read<size_t>(kregs.rsp + i*sizeof(size_t));
			printf("%016lx\n", value);
		}
		printf("\n");
	}
}

void Vm::print_fault_info() {
	cout << endl << m_fault << endl;
	print_stacktrace(m_fault.regs);
	cout << endl;
}

void Vm::dump_regs() {
	cout << regs() << endl;
}

void Vm::dump_memory() const {
	dump_memory(memsize());
}

void Vm::dump_memory(psize_t len) const {
	m_mmu.dump_memory(len, "dump");
}

void Vm::vm_err(const string& msg) {
	cout << endl << "[VM ERROR]" << endl;
	dump_regs();
	//dump_memory();

	// Dump current input file to mem
	if (m_files.exists("input")) {
		FileRef file = m_files.file_content("input");
		ofstream os("crash");
		os.write((const char*)file.ptr, file.length);
		assert(os.good());
		cout << "Dumped crash file of size " << file.length << endl;
		os.close();
	}

	die("%s\n", msg.c_str());
}

void Vm::dump(const string& filename) {
	m_mmu.dump_memory(m_mmu.size(), filename + ".dump");

	unordered_map<paddr_t, vaddr_t> memory_map;
	auto limits = s_elfs.elf().section_limits(".text");
	paddr_t paddr;
	for (vaddr_t vaddr = limits.first & PTL1_MASK;
	     vaddr < PAGE_CEIL(limits.second);
	     vaddr += PAGE_SIZE)
	{
		paddr = m_mmu.virt_to_phys(vaddr);
		memory_map[paddr] = vaddr;
	}

	ofstream ofs(filename + ".addr");
	assert(ofs.good());
	for (auto pair : memory_map) {
		ofs.seekp((pair.first / PAGE_SIZE)*sizeof(vaddr_t));
		ofs.write((char*)&pair.second, sizeof(vaddr_t));
	}
	ofs.close();
}

ostream& operator<<(ostream& os, const kvm_regs& regs) {
	// There's no way I write this with streams.
	char buf[512];
	snprintf(buf, sizeof(buf),
	         "rip: 0x%016llx\n"
	         "rax: 0x%016llx  rbx: 0x%016llx  rcx: 0x%016llx  rdx: 0x%016llx\n"
	         "rsi: 0x%016llx  rdi: 0x%016llx  rsp: 0x%016llx  rbp: 0x%016llx\n"
	         "r8:  0x%016llx  r9:  0x%016llx  r10: 0x%016llx  r11: 0x%016llx\n"
	         "r12: 0x%016llx  r13: 0x%016llx  r14: 0x%016llx  r15: 0x%016llx\n"
	         "rflags: 0x%016llx\n",
	         regs.rip, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi,
	         regs.rsp, regs.rbp, regs.r8, regs.r9, regs.r10, regs.r11, regs.r12,
	         regs.r13, regs.r14, regs.r15, regs.rflags);
	os << buf;

	// printf("rip: 0x%016llx\n", regs.rip);
	// printf("rax: 0x%016llx  rbx: 0x%016llx  rcx: 0x%016llx  rdx: 0x%016llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
	// printf("rsi: 0x%016llx  rdi: 0x%016llx  rsp: 0x%016llx  rbp: 0x%016llx\n", regs.rsi, regs.rdi, regs.rsp, regs.rbp);
	// printf("r8:  0x%016llx  r9:  0x%016llx  r10: 0x%016llx  r11: 0x%016llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
	// printf("r12: 0x%016llx  r13: 0x%016llx  r14: 0x%016llx  r15: 0x%016llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
	// printf("rflags: 0x%016llx\n", regs.rflags);
	return os;
}