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

#ifdef COVERAGE
	int vmx_pt = ioctl(g_kvm_fd, KVM_VMX_PT_SUPPORTED);
	ASSERT(vmx_pt != -1, "vmx_pt is not loaded");
	ASSERT(vmx_pt != -2, "Intel PT is not supported on this CPU");
#endif
}

Vm::Vm(vsize_t mem_size, const string& kernelpath, const string& filepath,
       const vector<string>& argv)
	: m_vm_fd(ioctl_chk(g_kvm_fd, KVM_CREATE_VM, 0))
	, m_vcpu_fd(ioctl_chk(m_vm_fd, KVM_CREATE_VCPU, 0))
	, m_vcpu_run((kvm_run*)mmap(NULL, ioctl_chk(g_kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0),
		                        PROT_READ|PROT_WRITE, MAP_SHARED, m_vcpu_fd, 0))
#ifdef COVERAGE
	, m_vmx_pt_fd(ioctl_chk(m_vcpu_fd, KVM_VMX_PT_SETUP_FD, 0))
	, m_vmx_pt((uint8_t*)mmap(NULL, ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, 0),
	                          PROT_READ, MAP_SHARED, m_vmx_pt_fd, 0))
#endif
	, m_regs(&m_vcpu_run->s.regs.regs)
	, m_sregs(&m_vcpu_run->s.regs.sregs)
	, m_elf(filepath)
	, m_kernel(kernelpath)
	, m_interpreter(NULL)
	, m_argv(argv)
	, m_mmu(m_vm_fd, mem_size)
	, m_running(false)
{
	setup_kvm();
}

Vm::Vm(const Vm& other)
	: m_vm_fd(ioctl_chk(g_kvm_fd, KVM_CREATE_VM, 0))
	, m_vcpu_fd(ioctl_chk(m_vm_fd, KVM_CREATE_VCPU, 0))
	, m_vcpu_run((kvm_run*)mmap(NULL, ioctl_chk(g_kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0),
		                        PROT_READ|PROT_WRITE, MAP_SHARED, m_vcpu_fd, 0))
#ifdef COVERAGE
	, m_vmx_pt_fd(ioctl_chk(m_vcpu_fd, KVM_VMX_PT_SETUP_FD, 0))
	, m_vmx_pt((uint8_t*)mmap(NULL, ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, 0),
	                          PROT_READ, MAP_SHARED, m_vmx_pt_fd, 0))
#endif
	, m_regs(&m_vcpu_run->s.regs.regs)
	, m_sregs(&m_vcpu_run->s.regs.sregs)
	, m_elf(other.m_elf)
	, m_kernel(other.m_kernel)
	, m_interpreter(NULL)
	, m_mmu(m_vm_fd, other.m_mmu)
	, m_running(false)
	, m_breakpoints_original_bytes(other.m_breakpoints_original_bytes)
{
	setup_kvm();

	// Copy registers
	memcpy(m_regs, other.m_regs, sizeof(*m_regs));

	// Copy sregs
	memcpy(m_sregs, other.m_sregs, sizeof(*m_sregs));

	// Indicate we have dirtied registers
	set_regs_dirty();
	set_sregs_dirty();
}

void Vm::init() {
	// Load kernel, and run it until it's ready
	Stats dummy;
	load_kernel();
	dbgprintf("Starting vm\n");
	run(dummy);
	dbgprintf("Kernel startup finished\n");

	// Load user elf
	load_elf();
}

void Vm::setup_kvm() {
	// Check if mmap failed
	ERROR_ON(m_vcpu_run == MAP_FAILED, "mmap kvm_run");
#ifdef COVERAGE
	ERROR_ON(m_vmx_pt == MAP_FAILED, "mmap vmx_pt");
#endif

	ioctl_chk(m_vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000);

	// Set special registers for long mode
	kvm_sregs sregs;
	ioctl_chk(m_vcpu_fd, KVM_GET_SREGS, &sregs);
	sregs.cr3  = Mmu::PAGE_TABLE_PADDR;
	sregs.cr4  = CR4_PAE | CR4_OSXMMEXCPT | CR4_OSFXSR;
	sregs.cr0  = CR0_PE | CR0_MP | CR0_ET| CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.efer = EFER_LME | EFER_LMA | EFER_SCE;

	// Setup segments
	// https://wiki.osdev.org/Global_Descriptor_Table
	// https://wiki.osdev.org/GDT_Tutorial
	kvm_segment seg = {
		.base     = 0,          // base address
		.limit    = 0xffffffff, // limit
		.selector = 0x8,        // index 1 (index 0 is null segment descriptor)
		.type     = 11,         // execute, read, accessed, idk why ???
		.present  = 1,          // bit P
		.dpl      = 0,          // Descriptor Privilege Level. 3 = user mode
		.db       = 0,          // Default operand size / Big
		.s        = 1,          // Descriptor type
		.l        = 1,          // Long: 64-bit segment. db must be zero
		.g        = 1           // Granularity: limit unit is byte and not page
	};
	sregs.cs = seg;
	seg.type     = 3;    // read, write, accessed, idk why ???
	seg.selector = 0x10; // index 2
	sregs.ds = sregs.es = sregs.fs = sregs.gs = sregs.ss = seg;
	ioctl_chk(m_vcpu_fd, KVM_SET_SREGS, &sregs);

	// Setup MSRs. I'd say MSR_STAR value is wrong, I just copy-pasted from
	// somewhere but it also works if that entry is removed so idk
	size_t sz = sizeof(kvm_msrs) + sizeof(kvm_msr_entry)*2;
	kvm_msrs* msrs = (kvm_msrs*)alloca(sz);
	memset(msrs, 0, sz);
	msrs->nmsrs = 3;
	msrs->entries[0] = {
		.index = MSR_LSTAR, // Long Syscall TARget
		.data = 1, //Mmu::SYSCALL_HANDLER_ADDR
	};
	msrs->entries[1] = {
		.index = MSR_STAR, // legacy Syscall TARget
		.data = 0x0020000800000000
	};
	msrs->entries[2] = {
		.index = MSR_SYSCALL_MASK,
		.data = 0x3f7fd5
	};
	ioctl_chk(m_vcpu_fd, KVM_SET_MSRS, msrs);

	// Setup cpuid
	sz = sizeof(kvm_cpuid2) + sizeof(kvm_cpuid_entry2)*100;
	kvm_cpuid2* cpuid = (kvm_cpuid2*)alloca(sz);
	memset(cpuid, 0, sz);
	cpuid->nent = 100;
	ioctl_chk(g_kvm_fd, KVM_GET_SUPPORTED_CPUID, cpuid);
	ioctl_chk(m_vcpu_fd, KVM_SET_CPUID2, cpuid);

	// Set debug
	kvm_guest_debug debug;
	memset(&debug, 0, sizeof(debug));
	debug.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP | KVM_GUESTDBG_USE_SW_BP;
	ioctl_chk(m_vcpu_fd, KVM_SET_GUEST_DEBUG, &debug);

	// Set register sync
	m_vcpu_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS;

#ifdef COVERAGE
	// Setup VMX PT
	vmx_pt_filter_iprs filter = {
		.a = 0x400000, // readelf text range
		.b = 0x410000
	};
	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_CONFIGURE_ADDR0, &filter);
	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_ENABLE_ADDR0, 0);

	ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_ENABLE, 0);
#endif
}

void Vm::load_elf() {
	// EXEC (no PIE) or DYN (PIE)
	if (m_elf.type() == ET_DYN)
		m_elf.set_base(0x400000);

	dbgprintf("Loading elf at 0x%lx\n", m_elf.load_addr());
	m_mmu.load_elf(m_elf.segments(), false);

	// Check if there's interpreter
	string interpreter_path = m_elf.interpreter();
	if (!interpreter_path.empty()) {
		TODO
		// Load interpreter and set RIP to its entry point
		m_interpreter = new ElfParser(interpreter_path);
		m_interpreter->set_base(0x7ffff7fcf000); // always DYN ?
		dbgprintf("Loading interpreter %s at 0x%lx\n", interpreter_path.c_str(),
		          m_interpreter->load_addr());
		m_mmu.load_elf(m_interpreter->segments(), false);
		m_regs->rip = m_interpreter->entry();
	} else {
		// Set RIP to elf entry point
		m_regs->rip = m_elf.entry();
	}

	// Allocate stack
	// http://articles.manugarg.com/aboutelfauxiliaryvectors.html
	m_regs->rsp = m_mmu.alloc_stack(false);

	// NULL
	m_regs->rsp -= 16;
	m_mmu.write<vaddr_t>(m_regs->rsp, 0);
	m_mmu.write<vaddr_t>(m_regs->rsp + 8, 0);

	// Random bytes for auxv. Seed is not initialized
	m_regs->rsp -= 16;
	vaddr_t random_bytes = m_regs->rsp;
	for (int i = 0; i < 16; i++)
		m_mmu.write<uint8_t>(random_bytes + i, rand());

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
	//regs->rsp = (regs->rsp - 0x7) & ~0x7;

	// Set up auxp
	phinfo_t phinfo      = m_elf.phinfo();
	vaddr_t  load_addr   = m_elf.load_addr();
	vaddr_t  interp_base = (m_interpreter ? m_interpreter->base() : 0);
	Elf64_auxv_t auxv[]  = {
		{AT_PHDR,   {load_addr + phinfo.e_phoff}}, // Pointer to program headers
		{AT_PHENT,  {phinfo.e_phentsize}},         // Size of each entry
		{AT_PHNUM,  {phinfo.e_phnum}},             // Number of entries
		{AT_PAGESZ, {PAGE_SIZE}},                  // Page size
		{AT_BASE,   {interp_base}},                // Interpreter base address
		{AT_ENTRY,  {m_elf.entry()}},              // Entry point of the program
		{AT_RANDOM, {random_bytes}},               // Address of 16 random bytes
		{AT_EXECFN, {argv_addrs[0]}},              // Filename of the program
		{AT_NULL,   {0}},                          // Auxv end
	};
	m_regs->rsp -= sizeof(auxv);
	m_mmu.write_mem(m_regs->rsp, auxv, sizeof(auxv));

	// Set up envp
	m_regs->rsp -= 8;
	m_mmu.write<vaddr_t>(m_regs->rsp, 0);

	// Set up argv
	for (auto it = argv_addrs.rbegin(); it != argv_addrs.rend(); ++it) {
		m_regs->rsp -= 8;
		m_mmu.write<vaddr_t>(m_regs->rsp, *it);
	}

	// Set up argc
	m_regs->rsp -= 8;
	m_mmu.write<uint64_t>(m_regs->rsp, m_argv.size());

	m_regs->rflags = 2;

	set_regs_dirty();

	dbgprintf("Elf loaded and rip set to 0x%llx\n", m_regs->rip);
}

void Vm::load_kernel() {
	// Check it's static and no PIE
	ASSERT(m_kernel.type() == ET_EXEC, "Kernel is PIE?");
	ASSERT(m_kernel.interpreter().empty(), "Kernel is dynamically linked");
	dbgprintf("Loading kernel at 0x%lx\n", m_kernel.load_addr());

	// Load kernel to memory, allocate stack and set up registers
	m_mmu.load_elf(m_kernel.segments(), true);
	m_regs->rsp = m_mmu.alloc_stack(true) - 0x10;
	m_regs->rflags = 2;
	m_regs->rip = m_kernel.entry();
	set_regs_dirty();

	dbgprintf("Kernel loaded and rip set to 0x%llx\n", m_regs->rip);
}

void Vm::set_regs_dirty() {
	m_vcpu_run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
}

void Vm::set_sregs_dirty() {
	m_vcpu_run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
}

psize_t Vm::memsize() const {
	return m_mmu.size();
}

void Vm::reset(const Vm& other, Stats& stats) {
	cycle_t cycles;

	// Reset mmu
	cycles = rdtsc2();
	m_mmu.reset(other.m_mmu);
	stats.reset1_cycles += rdtsc2() - cycles;

	// Reset registers
	cycles = rdtsc2();
	memcpy(m_regs, other.m_regs, sizeof(*m_regs));
	stats.reset2_cycles += rdtsc2() - cycles;

	// Reset sregs
	cycles = rdtsc2();
	memcpy(m_sregs, other.m_sregs, sizeof(*m_sregs));
	stats.reset3_cycles += rdtsc2() - cycles;

	// Indicate we have dirtied registers
	set_regs_dirty();
	set_sregs_dirty();

	// Reset other VM state
	m_breakpoints_original_bytes = other.m_breakpoints_original_bytes;
}

void Vm::run(Stats& stats) {
	cycle_t cycles;
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
					cycles = rdtsc2();
					handle_hypercall();
					//handle_syscall();
					stats.syscall_cycles += rdtsc2() - cycles;
					stats.vm_exits_sys++;
				} else {
					vm_err("IO");
				}
				break;

			case KVM_EXIT_DEBUG:
				// TODO: VmExitReason?
				printf("breakpoint hit\n");
				dump_regs();
				m_regs->rip += 1;
				set_regs_dirty();
				cout << endl;
				stats.vm_exits_debug++;
				break;
				//m_running = false;
				//return;

			case KVM_EXIT_VMX_PT_TOPA_MAIN_FULL:
				stats.vm_exits_cov++;
				get_coverage();
				break;

			case KVM_EXIT_FAIL_ENTRY:
				vm_err("KVM_EXIT_FAIL_ENTRY");

			case KVM_EXIT_INTERNAL_ERROR:
				vm_err("KVM_EXIT_INTERNAL_ERROR");

			case KVM_EXIT_SHUTDOWN:
				vm_err("KVM_EXIT_SHUTDOWN");

			default:
				vm_err("UNKNOWN EXIT " + to_string(m_vcpu_run->exit_reason));
		}
	}
}

void Vm::run_until(vaddr_t pc, Stats& stats) {
	set_breakpoint(pc);
	run(stats);
	remove_breakpoint(pc);

	ASSERT(m_regs->rip == pc, "run until stopped at 0x%llx instead of 0x%lx",
		   m_regs->rip, pc);
}

void Vm::get_coverage() {
	size_t size = ioctl_chk(m_vmx_pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, 0);
	//printf("full %lu\n", size);
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

void Vm::set_file(const string& filename, const string& content) {
	struct iovec iov = {
		.iov_base = (void*)content.c_str(),
		.iov_len  = content.size()
	};
	m_file_contents[filename] = iov;
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
	struct iovec& iov = m_file_contents["test"];
	os.write((char*)iov.iov_base, iov.iov_len);
	assert(os.good());
	cout << "Dumped crash file of size " << iov.iov_len << endl;

	die("%s\n", msg.c_str());
}