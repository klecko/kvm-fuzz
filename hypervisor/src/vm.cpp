#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "vm.h"

using namespace std;

int g_kvm_fd = -1;

void init_kvm() {
	g_kvm_fd = open("/dev/kvm", O_RDWR);
	ERROR_ON(g_kvm_fd == -1, "open /dev/kvm");

	int api_ver = ioctl(g_kvm_fd, KVM_GET_API_VERSION, 0);
	ASSERT(api_ver == KVM_API_VERSION, "kvm api version doesn't match: %d vs %d",
	       KVM_API_VERSION, api_ver);

#ifdef ENABLE_COVERAGE
	int vmx_pt = ioctl(g_kvm_fd, KVM_VMX_PT_SUPPORTED);
	ASSERT(vmx_pt != -1, "vmx_pt is not loaded");
	ASSERT(vmx_pt != -2, "Intel PT is not supported on this CPU");
#endif
}

Vm::Vm(vsize_t mem_size, const string& kernelpath, const string& filepath,
       const vector<string>& argv)
	: m_vm_fd(create_vm())
	, m_elf(filepath)
	, m_kernel(kernelpath)
	, m_interpreter(NULL)
	, m_argv(argv)
	, m_mmu(m_vm_fd, m_vcpu_fd, mem_size)
	, m_running(false)
{
	load_elfs();

	// This has to be done after elfs have been loaded an relocated, so we know
	// the address range we want to get coverage from
#ifdef ENABLE_COVERAGE
	setup_coverage();
#endif

	setup_kvm();

	setup_kernel_execution();

	printf("Ready to run!\n");
}

Vm::Vm(const Vm& other)
	: m_vm_fd(create_vm())
	, m_elf(other.m_elf)
	, m_kernel(other.m_kernel)
	, m_interpreter(other.m_interpreter)
	, m_argv(other.m_argv)
	, m_mmu(m_vm_fd, m_vcpu_fd, other.m_mmu)
	, m_running(false)
	, m_breakpoints_original_bytes(other.m_breakpoints_original_bytes)
	, m_file_contents(other.m_file_contents)
{
	// Elfs are already relocated by the other VM, we can init vmx pt
#ifdef ENABLE_COVERAGE
	setup_coverage();
#endif

	setup_kvm();

	// Copy registers
	memcpy(m_regs, other.m_regs, sizeof(*m_regs));

	// Copy sregs
	memcpy(m_sregs, other.m_sregs, sizeof(*m_sregs));

	// Copy MSRs
	size_t sz = sizeof(kvm_msrs) + sizeof(kvm_msr_entry)*5;
	kvm_msrs* msrs = (kvm_msrs*)alloca(sz);
	msrs->nmsrs = 5;
	msrs->entries[0].index = MSR_LSTAR;
	msrs->entries[1].index = MSR_STAR;
	msrs->entries[2].index = MSR_SYSCALL_MASK;
	msrs->entries[3].index = MSR_FS_BASE;
	msrs->entries[4].index = MSR_GS_BASE;
	ioctl_chk(other.m_vcpu_fd, KVM_GET_MSRS, msrs);
	ioctl_chk(m_vcpu_fd, KVM_SET_MSRS, msrs);

	// Indicate we have dirtied registers
	set_regs_dirty();
	set_sregs_dirty();
}

int Vm::create_vm() {
	m_vm_fd = ioctl_chk(g_kvm_fd, KVM_CREATE_VM, 0);
#ifdef ENABLE_KVM_DIRTY_LOG_RING
	int max_size = ioctl_chk(m_vm_fd, KVM_CHECK_EXTENSION, KVM_CAP_DIRTY_LOG_RING);
	ASSERT(max_size, "kvm dirty log ring not available");

	kvm_enable_cap cap = {
		.cap = KVM_CAP_DIRTY_LOG_RING,
		.args = {max_size}
	};
	ioctl_chk(m_vm_fd, KVM_ENABLE_CAP, &cap);
#endif

	m_vcpu_fd = ioctl_chk(m_vm_fd, KVM_CREATE_VCPU, 0);

	size_t vcpu_run_size = ioctl_chk(g_kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	m_vcpu_run = (kvm_run*)mmap(NULL, vcpu_run_size, PROT_READ|PROT_WRITE,
	                            MAP_SHARED, m_vcpu_fd, 0);
	ERROR_ON(m_vcpu_run == MAP_FAILED, "mmap vcpu_run");

	m_regs  = &m_vcpu_run->s.regs.regs;
	m_sregs = &m_vcpu_run->s.regs.sregs;
	return m_vm_fd;
}

void Vm::setup_kvm() {
	ioctl_chk(m_vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000);

	// Set special registers for long mode
	kvm_sregs sregs;
	ioctl_chk(m_vcpu_fd, KVM_GET_SREGS, &sregs);
	sregs.cr3  = Mmu::PAGE_TABLE_PADDR;
	sregs.cr4  = CR4_PAE | CR4_OSXMMEXCPT | CR4_OSFXSR;
	sregs.cr0  = CR0_PE | CR0_MP | CR0_ET| CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.efer = EFER_LME | EFER_LMA | EFER_SCE;

	// Setup dummy segments. This is needed so we start directly in long mode.
	// However, this doesn't set the GDT. It will be properly set by the kernel
	// inside the VM.
	kvm_segment seg = {
		.base     = 0,          // base address
		.limit    = 0xffffffff, // limit
		.selector = 0x8,        // index 1 (index 0 is null segment descriptor)
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

	// Set debug
	set_single_step(false);

	// Set register sync
	m_vcpu_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS;
}

void Vm::setup_coverage() {
	// Get coverage range. Elf should have been loaded by now
	auto limits = m_elf.section_limits(".text");
	vmx_pt_filter_iprs filter0 = { limits.first, limits.second };
	printf_once("Coverage range: 0x%llx to 0x%llx\n", filter0.a, filter0.b);

	// VMX PT
	m_vmx_pt_fd = ioctl_chk(m_vcpu_fd, KVM_VMX_PT_SETUP_FD, 0);
	size_t vmx_pt_size = ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, 0);
	m_vmx_pt = (uint8_t*)mmap(NULL, vmx_pt_size, PROT_READ|PROT_WRITE,
	                          MAP_SHARED, m_vmx_pt_fd, 0);
	ERROR_ON(m_vmx_pt == MAP_FAILED, "mmap vmx_pt");
	m_vmx_pt_bitmap = (uint8_t*)malloc(COVERAGE_BITMAP_SIZE);

	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_CONFIGURE_ADDR0, &filter0);
	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_ENABLE_ADDR0, 0);
	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_ENABLE, 0);

	// libxdc
	typedef void* (*page_fetcher_t)(void*, uint64_t, bool*);
	typedef void  (*bb_callback_t)(void*, uint64_t, uint64_t);
	typedef void  (*edge_callback_t)(void*, uint64_t, uint64_t);
	uint64_t filter[4][2] = {0};
	filter[0][0] = filter0.a;
	filter[0][1] = filter0.b;
	m_vmx_pt_decoder = libxdc_init(filter, (page_fetcher_t)&Vm::fetch_page,
	                               this, m_vmx_pt_bitmap, COVERAGE_BITMAP_SIZE);
	//libxdc_register_bb_callback(decoder, (bb_callback_t)test_bb, NULL);
	//libxdc_register_edge_callback(decoder, (edge_callback_t)test_edge, NULL);
	//libxdc_enable_tracing(decoder);
}

void Vm::load_elfs() {
	// First, the kernel
	// Check it's static and no PIE and load it
	ASSERT(m_kernel.type() == ET_EXEC, "Kernel is PIE?");
	ASSERT(m_kernel.interpreter().empty(), "Kernel is dynamically linked");
	dbgprintf("Loading kernel at 0x%lx\n", m_kernel.load_addr());
	m_mmu.load_elf(m_kernel.segments(), true);

	// Now, user elf. Assign base address if it's DYN (PIE) and load it
	if (m_elf.type() == ET_DYN)
		m_elf.set_base(Mmu::ELF_ADDR);
	dbgprintf("Loading elf at 0x%lx\n", m_elf.load_addr());
	m_mmu.load_elf(m_elf.segments(), false);

	// Check if user elf has interpreter
	string interpreter_path = m_elf.interpreter();
	if (!interpreter_path.empty()) {
		m_interpreter = new ElfParser(interpreter_path);
		ASSERT(m_interpreter->type() == ET_DYN, "interpreter not ET_DYN?");
		m_interpreter->set_base(0x400000000000);
		dbgprintf("Loading interpreter %s at 0x%lx\n",
		          m_interpreter->path().c_str(), m_interpreter->load_addr());
		m_mmu.load_elf(m_interpreter->segments(), false);
	}
}

void Vm::setup_kernel_execution() {
	m_regs->rsp = m_mmu.alloc_kernel_stack();
	m_regs->rflags = 2; // TODO: what about IOPL
	m_regs->rip = m_kernel.entry();

	// Let's write argv to kernel stack, so he can then write it to user stack
	// Write argv strings saving pointers to each arg
	vector<vaddr_t> argv_addrs;
	for (const string& arg : m_argv) {
		m_regs->rsp -= arg.size() + 1;
		m_mmu.write_mem(m_regs->rsp, arg.c_str(), arg.size()+1);
		argv_addrs.push_back(m_regs->rsp);
	}
	argv_addrs.push_back(0); // null ptr, end of argv

	// Align rsp
	m_regs->rsp &= ~0x7;

	// Set up argv
	for (auto it = argv_addrs.rbegin(); it != argv_addrs.rend(); ++it) {
		m_regs->rsp -= 8;
		m_mmu.write<vaddr_t>(m_regs->rsp, *it);
	}

	// Setup args for kmain
	m_regs->rdi = m_argv.size(); // argc
	m_regs->rsi = m_regs->rsp;   // argv
	set_regs_dirty();
}

void Vm::set_regs_dirty() {
	m_vcpu_run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
}

void Vm::set_sregs_dirty() {
	m_vcpu_run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
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

psize_t Vm::memsize() const {
	return m_mmu.size();
}

FaultInfo Vm::fault() const {
	return m_fault;
}

uint8_t* Vm::coverage_bitmap() const {
	return m_vmx_pt_bitmap;
}

void Vm::reset_coverage() {
	memset(m_vmx_pt_bitmap, 0, COVERAGE_BITMAP_SIZE);
}

void Vm::reset(const Vm& other, Stats& stats) {
	// Reset mmu, regs and sregs
	stats.reset_pages += m_mmu.reset(other.m_mmu);
	memcpy(m_regs, other.m_regs, sizeof(*m_regs));
	memcpy(m_sregs, other.m_sregs, sizeof(*m_sregs));

	// Indicate we have dirtied registers
	set_regs_dirty();
	set_sregs_dirty();

	// Reset other VM state
	m_breakpoints_original_bytes = other.m_breakpoints_original_bytes;
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
				m_running = false;
				reason = RunEndReason::Debug;
				stats.vm_exits_debug++;
				break;

			case KVM_EXIT_VMX_PT_TOPA_MAIN_FULL:
				stats.vm_exits_cov++;
				update_coverage(stats);
				break;

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

#ifdef ENABLE_COVERAGE
	// Before returning, update coverage
	update_coverage(stats);
#endif

	return reason;
}

void Vm::run_until(vaddr_t pc, Stats& stats) {
	set_breakpoint(pc);
	RunEndReason reason = run(stats);
	remove_breakpoint(pc);

	ASSERT(m_regs->rip == pc, "run until stopped at 0x%llx instead of 0x%lx",
		   m_regs->rip, pc);
	ASSERT(reason == RunEndReason::Debug, "run until end reason: %d", reason);
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

void* Vm::fetch_page(uint64_t page, bool* success) {
	thread_local unordered_map<uint64_t, void*> cache;
	thread_local uint64_t last_page = 0;
	thread_local void* last_result = NULL;
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

		//free(buf);
	}
	stats.update_cov_cycles += rdtsc2() - cycles;
}

#ifdef HW_BPS
void Vm::set_breakpoint(vaddr_t addr) {
	kvm_debugregs debug;
	memset(&debug, 0, sizeof(debug));
	ioctl_chk(vcpu.fd, KVM_GET_DEBUGREGS, &debug);

	// Check if breakpoint is already set
	bool bp_activated;
	int j = -1;
	for (int i = 0; i < 4; i++) {
		bp_activated = (debug.dr7 & (1 << (i*2))) != 0;
		if (bp_activated && debug.db[i] == addr)
			return;
		else if (!bp_activated)
			j = i;
	}

	// Set breakpoint
	ASSERT(j != -1, "No breakpoint slot left, trying to set bp 0x%lx\n", addr);
	dbgprintf("Setting bp 0x%lx to slot %d\n", addr, j);
	debug.dr7 |= 1 << (j*2);
	debug.db[j] = addr;
	ioctl_chk(vcpu.fd, KVM_SET_DEBUGREGS, &debug);

	// I have no idea why I have to do this despite having already used
	// KVM_SET_GUEST_DEBUG. It looks like setting registers with
	// KVM_SET_DEBUGREGS saves registers (they can be retrieved with
	// KVM_GET_DEBUGREGS) but they actually don't work, whereas with
	// KVM_SET_GUEST_DEBUG they work, but they can not be retrieved.
	kvm_guest_debug debug2;
	memset(&debug2, 0, sizeof(debug2));
	debug2.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
	for (int i = 0; i < 4; i++)
		debug2.arch.debugreg[i] = debug.db[i];
	debug2.arch.debugreg[7] = debug.dr7;
	ioctl_chk(vcpu.fd, KVM_SET_GUEST_DEBUG, &debug2);
}

void Vm::remove_breakpoint(vaddr_t addr) {
	kvm_debugregs debug;
	memset(&debug, 0, sizeof(debug));
	ioctl_chk(vcpu.fd, KVM_GET_DEBUGREGS, &debug);

	// Check if breakpoint is already set
	bool bp_activated;
	int j = -1;
	for (int i = 0; i < 4; i++) {
		bp_activated = (debug.dr7 & (1 << (i*2))) != 0;
		if (bp_activated && debug.db[i] == addr) {
			j = i;
			break;
		}
	}

	// Remove breakpoint
	ASSERT(j != -1, "Trying to remove breakpoint not set: 0x%lx\n", addr);
	dbgprintf("Removing bp 0x%lx from slot %d\n", addr, j);
	debug.dr7 &= ~(1 << (j*2));
	ioctl_chk(vcpu.fd, KVM_SET_DEBUGREGS, &debug);

	// I have no idea why I have to do this despite having already used
	// KVM_SET_GUEST_DEBUG. It looks like setting registers with
	// KVM_SET_DEBUGREGS saves registers (they can be retrieved with
	// KVM_GET_DEBUGREGS) but they actually don't work, whereas with
	// KVM_SET_GUEST_DEBUG they work, but they can not be retrieved.
	kvm_guest_debug debug2;
	memset(&debug2, 0, sizeof(debug2));
	debug2.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
	for (int i = 0; i < 4; i++)
		debug2.arch.debugreg[i] = debug.db[i];
	debug2.arch.debugreg[7] = debug.dr7;
	ioctl_chk(vcpu.fd, KVM_SET_GUEST_DEBUG, &debug2);
}
#endif

#define SW_BPS
#ifdef SW_BPS
void Vm::set_breakpoint(vaddr_t addr) {
	uint8_t* p = m_mmu.get(addr);
	ASSERT(*p != 0xCC, "Trying to set breakpoint twice: 0x%lx", addr);
	m_breakpoints_original_bytes[addr] = *p;
	*p = 0xCC;
}

void Vm::remove_breakpoint(vaddr_t addr) {
	uint8_t* p = m_mmu.get(addr);
	ASSERT(*p == 0xCC, "Trying to remove not existing breakpoint: 0x%lx", addr);
	*p = m_breakpoints_original_bytes[addr];
	m_breakpoints_original_bytes.erase(addr);
}
#endif

void Vm::set_file(const string& filename, const string& content, bool check) {
	bool existed = m_file_contents.count(filename);
	file_t& file = m_file_contents[filename];
	file.data    = (const void*)content.c_str();
	file.length  = content.size();
	if (existed) {
		// File already existed. If kernel submitted a buffer for it, write
		// content into its memory.
		ASSERT(!check || file.guest_buf, "kernel didn't submit buf for file %s",
				filename.c_str());
		if (file.guest_buf)
			m_mmu.write_mem(file.guest_buf, file.data, file.length);
	} else {
		// File didn't exist. Set guest buffer address to 0, and wait for guest
		// kernel to do hc_set_file_buf.
		file.guest_buf = 0;
	};
}

vaddr_t Vm::resolve_symbol(const string& symbol_name) {
	for (const symbol_t symbol : m_elf.symbols())
		if (symbol.name == symbol_name)
			return symbol.value;
	ASSERT(false, "not found symbol: %s", symbol_name.c_str());
}

void Vm::dump_regs() {
	printf("rip: 0x%016llX\n", m_regs->rip);
	printf("rax: 0x%016llX  rbx: 0x%016llX  rcx: 0x%016llX  rdx: 0x%016llX\n", m_regs->rax, m_regs->rbx, m_regs->rcx, m_regs->rdx);
	printf("rsi: 0x%016llX  rdi: 0x%016llX  rsp: 0x%016llX  rbp: 0x%016llX\n", m_regs->rsi, m_regs->rdi, m_regs->rsp, m_regs->rbp);
	printf("r8:  0x%016llX  r9:  0x%016llX  r10: 0x%016llX  r11: 0x%016llX\n", m_regs->r8, m_regs->r9, m_regs->r10, m_regs->r11);
	printf("r12: 0x%016llX  r13: 0x%016llX  r14: 0x%016llX  r15: 0x%016llX\n", m_regs->r12, m_regs->r13, m_regs->r14, m_regs->r15);
	printf("rflags: 0x%016llX\n", m_regs->rflags);

	/* kvm_fpu fregs;
	ioctl_chk(vcpu.fd, KVM_GET_FPU, &regs);
	for (int i = 0; i < 16; i++) {
		printf("xmm%02d: %08Lf  ", i, *(long double*)&fregs.xmm[i]);
		if ((i+1)%4 == 0)
			printf("\n");
	} */
}

void Vm::dump_memory() const {
	dump_memory(memsize());
}

void Vm::dump_memory(psize_t len) const {
	m_mmu.dump_memory(len);
}

void Vm::vm_err(const string& msg) {
	cout << endl << "[VM ERROR]" << endl;
	dump_regs();
	//dump_memory();

	// Dump current input file to mem
	ofstream os("crash");
	file_t& buf = m_file_contents["test"];
	os.write((char*)buf.data, buf.length);
	assert(os.good());
	cout << "Dumped crash file of size " << buf.length << endl;

	die("%s\n", msg.c_str());
}