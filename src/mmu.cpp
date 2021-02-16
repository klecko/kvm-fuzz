#include <iostream>
#include <fstream>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <string.h>
#include <stdexcept>
#include "mmu.h"
#include "kvm_aux.h"

using namespace std;

// out 16, al; sysret
const unsigned char SYSCALL_HANDLER[] = "\xe6\x10\x48\x0f\x07";

const int Mmu::PageWalker::FLAGS = PDE64_PRESENT | PDE64_RW | PDE64_USER;

Mmu::PageWalker::PageWalker(vaddr_t vaddr, Mmu& mmu)
	: m_start(vaddr)
	, m_len(0)
	, m_mmu(mmu)
	, m_offset(0)
	, m_ptl4_i(PTL4_INDEX(vaddr))
	, m_ptl3_i(PTL3_INDEX(vaddr))
	, m_ptl2_i(PTL2_INDEX(vaddr))
	, m_ptl1_i(PTL1_INDEX(vaddr))
{
	update_ptl3();
	update_ptl2();
	update_ptl1();
}

Mmu::PageWalker::PageWalker(vaddr_t start, vsize_t len, Mmu& mmu)
	: PageWalker(start, mmu)
{
	m_len = len;
}

vaddr_t Mmu::PageWalker::start() {
	return m_start;
}

vaddr_t Mmu::PageWalker::len() {
	return m_len;
}

paddr_t* Mmu::PageWalker::pte() {
	return &m_ptl1[m_ptl1_i];
}

vsize_t Mmu::PageWalker::offset() {
	return m_offset;
}

vaddr_t Mmu::PageWalker::vaddr() {
	return m_start + m_offset;
}

paddr_t Mmu::PageWalker::paddr() {
	ASSERT(*pte(), "Trying to translate not mapped vaddr: 0x%lx", vaddr());
	return (*pte() & PTL1_MASK) + PAGE_OFFSET(vaddr());
}

vsize_t Mmu::PageWalker::page_size() {
	vsize_t ret = PAGE_SIZE - PAGE_OFFSET(vaddr());
	if (m_len && m_offset < m_len)
		ret = min(ret, m_len - m_offset);
	return ret;
}

uint64_t Mmu::PageWalker::flags() {
	ASSERT(*pte(), "Trying to get flags of not mapped vaddr: 0x%lx", vaddr());
	return PAGE_OFFSET(*pte()); // FIXME NX
}

void Mmu::PageWalker::set_flags(uint64_t flags) {
	ASSERT(*pte(), "Trying to set flags to not mapped vaddr: 0x%lx", vaddr());
	ASSERT(PAGE_OFFSET(flags) == flags, "bad page flags: %lx", flags);
	*pte() |= flags;
}

void Mmu::PageWalker::alloc_frame(uint64_t flags) {
	ASSERT(!*pte(), "vaddr already mapped: 0x%lx", vaddr());
	*pte() = m_mmu.alloc_frame() | flags;
	dbgprintf("Alloc frame: 0x%lx mapped to 0x%lx with flags 0x%lx\n",
	          vaddr(), *pte() & PTL1_MASK, flags);
}

bool Mmu::PageWalker::next() {
	// Advance one PTE, update current offset and return whether there are more
	// pages left
	next_ptl1_entry();

	m_offset += PAGE_SIZE - PAGE_OFFSET(vaddr());

	return m_offset < m_len;
}

void Mmu::PageWalker::update_ptl3() {
	if (!m_mmu.m_ptl4[m_ptl4_i]) {
		m_mmu.m_ptl4[m_ptl4_i] = m_mmu.alloc_frame() | FLAGS;
	}
	m_ptl3 = (paddr_t*)(m_mmu.m_memory + (m_mmu.m_ptl4[m_ptl4_i] & PTL1_MASK));
}

void Mmu::PageWalker::update_ptl2() {
	if (!m_ptl3[m_ptl3_i]) {
		m_ptl3[m_ptl3_i] = m_mmu.alloc_frame() | FLAGS;
	}
	m_ptl2 = (paddr_t*)(m_mmu.m_memory + (m_ptl3[m_ptl3_i] & PTL1_MASK));
}

void Mmu::PageWalker::update_ptl1() {
	if (!m_ptl2[m_ptl2_i]) {
		m_ptl2[m_ptl2_i] = m_mmu.alloc_frame() | FLAGS;
	}
	m_ptl1 = (paddr_t*)(m_mmu.m_memory + (m_ptl2[m_ptl2_i] & PTL1_MASK));
}

void Mmu::PageWalker::next_ptl4_entry() {
	m_ptl4_i++;
	ASSERT(m_ptl4_i != PTRS_PER_PTL4, "PageWalker: OOB?");
	update_ptl3();
}

void Mmu::PageWalker::next_ptl3_entry() {
	m_ptl3_i++;
	if (m_ptl3_i == PTRS_PER_PTL3) {
		m_ptl3_i = 0;
		next_ptl4_entry();
	}
	update_ptl2();
}

void Mmu::PageWalker::next_ptl2_entry() {
	m_ptl2_i++;
	if (m_ptl2_i == PTRS_PER_PTL2) {
		m_ptl2_i = 0;
		next_ptl3_entry();
	}
	update_ptl1();
}

void Mmu::PageWalker::next_ptl1_entry() {
	m_ptl1_i++;
	if (m_ptl1_i == PTRS_PER_PTL1) {
		m_ptl1_i = 0;
		next_ptl2_entry();
	}
}


Mmu::Mmu(int vm_fd, size_t mem_size)
	: m_vm_fd(vm_fd)
	, m_memory((uint8_t*)mmap(NULL, mem_size, PROT_READ|PROT_WRITE,
	                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0))
	, m_length(mem_size)
	, m_ptl4((paddr_t*)(m_memory + PAGE_TABLE_PADDR))
	, m_next_page_alloc(PAGE_TABLE_PADDR + 0x1000)
	, m_dirty_bits(m_length/PAGE_SIZE)
	, m_dirty_bitmap(new uint8_t[m_dirty_bits/8])
	, m_brk(0)
	, m_min_brk(0)
{
	ERROR_ON(m_memory == MAP_FAILED, "mmap mmu memory");

	madvise(m_memory, m_length, MADV_MERGEABLE);

	memset(m_dirty_bitmap, 0, m_dirty_bits/8);

	struct kvm_userspace_memory_region memreg = {
		.slot = 0,
		.flags = KVM_MEM_LOG_DIRTY_PAGES,
		.guest_phys_addr = 0,
		.memory_size = mem_size,
		.userspace_addr = (unsigned long)m_memory
	};
	ioctl_chk(m_vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg);

	// Set syscall handler
	memcpy(
		m_memory + SYSCALL_HANDLER_ADDR,
		SYSCALL_HANDLER,
		sizeof(SYSCALL_HANDLER)
	);

	init_page_table();
}

Mmu::Mmu(int vm_fd, const Mmu& other)
	: Mmu(vm_fd, other.m_length)
{
	m_next_page_alloc = other.m_next_page_alloc;
	m_brk             = other.m_brk;
	m_min_brk         = other.m_min_brk;
	memcpy(m_memory, other.m_memory, m_length);

	// Reset kvm dirty bitmap
	memset(m_dirty_bitmap, 0xFF, m_dirty_bits/8);
	kvm_clear_dirty_log clear_dirty = {
		.slot = 0,
		.num_pages = m_dirty_bits,
		.first_page = 0,
		.dirty_bitmap = m_dirty_bitmap,
	};
	ioctl_chk(m_vm_fd, KVM_CLEAR_DIRTY_LOG, &clear_dirty);
	memset(m_dirty_bitmap, 0, m_dirty_bits/8);
}

Mmu::~Mmu() {
	munmap(m_memory, m_length);
	delete[] m_dirty_bitmap;
}

void Mmu::init_page_table() {
	// Identity map the first 4K, as writable without PDE64_USER
	paddr_t* pte = get_pte(0);
	*pte = 0 | PDE64_PRESENT | PDE64_RW;
}

psize_t Mmu::size() const {
	return m_length;
}

vaddr_t Mmu::brk() const {
	return m_brk;
}

bool Mmu::set_brk(vaddr_t new_brk) {
	dbgprintf("trying to set brk to %lX\n", new_brk);
	if (new_brk < m_min_brk)
		return false;

	// Allocate space if needed
	vaddr_t next_page = (m_brk + 0xFFF) & ~0xFFF;
	if (new_brk > next_page) {
		alloc(next_page, new_brk - next_page, PDE64_RW);
	}

	dbgprintf("brk set to %lX\n", new_brk);
	m_brk = new_brk;
	return true;
}

void Mmu::reset(const Mmu& other) {
	// Get dirty pages bitmap
	kvm_dirty_log dirty = {
		.slot = 0,
		.dirty_bitmap = m_dirty_bitmap
	};
	ioctl_chk(m_vm_fd, KVM_GET_DIRTY_LOG, &dirty);

	// Reset pages
	size_t count = 0;
	uint8_t byte, bit;
	paddr_t paddr;
	for (size_t i = 0; i < m_dirty_bits; i++) {
		byte = m_dirty_bitmap[i/8];
		bit  = byte & (1 << (i%8));
		if (bit) {
			count++;
			paddr = i*PAGE_SIZE;
			memcpy(m_memory + paddr, other.m_memory + paddr, PAGE_SIZE);
		}
	}
	//printf("resetted %lu pages\n", count);

	// Reset bitmap
	memset(dirty.dirty_bitmap, 0, m_dirty_bits/8);
}

paddr_t Mmu::alloc_frame() {
	ASSERT(m_next_page_alloc <= m_length - PAGE_SIZE, "OOM");
	paddr_t ret = m_next_page_alloc;
	m_next_page_alloc += PAGE_SIZE;
	return ret;
}

paddr_t* Mmu::get_pte(vaddr_t vaddr) {
	PageWalker walker(vaddr, *this);
	return walker.pte();
}

paddr_t Mmu::virt_to_phys(vaddr_t vaddr) {
	PageWalker walker(vaddr, *this);
	return walker.paddr();
}

uint8_t* Mmu::get(vaddr_t guest) {
	return m_memory + virt_to_phys(guest);
}

void Mmu::alloc(vaddr_t start, vsize_t len, uint64_t flags) {
	ASSERT(len != 0, "alloc %lx zero length", start);
	flags |= PDE64_PRESENT | PDE64_USER;
	PageWalker pages(start, len, *this);
	do {
		pages.alloc_frame(flags);
	} while (pages.next());
}

vaddr_t Mmu::alloc_stack() {
	// Allocate stack as writable and not executable
	alloc(STACK_START_ADDR - STACK_SIZE, STACK_SIZE, PDE64_RW | PDE64_NX);
	return STACK_START_ADDR;
}

void Mmu::read_mem(void* dst, vaddr_t src, vsize_t len) {
	PageWalker pages(src, len, *this);
	do {
		// We don't need to check read access: write only pages don't exist
		// in x86
		memcpy(
			(uint8_t*)dst + pages.offset(),
			m_memory + pages.paddr(),
			pages.page_size()
		);
	} while (pages.next());
}

void Mmu::write_mem(vaddr_t dst, const void* src, vsize_t len, bool chk_perms) {
	PageWalker pages(dst, len, *this);
	do {
		ASSERT(!chk_perms || (pages.flags() & PDE64_RW),
		       "writing to not writable page %lx", pages.vaddr());
		memcpy(
			m_memory + pages.paddr(),
			(uint8_t*)src + pages.offset(),
			pages.page_size()
		);
	} while (pages.next());
}

void Mmu::set_mem(vaddr_t addr, int c, vsize_t len, bool chk_perms) {
	PageWalker pages(addr, len, *this);
	do {
		ASSERT(!chk_perms || (pages.flags() & PDE64_RW),
		       "memset to not writable page %lx", pages.vaddr());
		memset(m_memory + pages.paddr(), c, pages.page_size());
	} while (pages.next());
}

string Mmu::read_string(vaddr_t addr) {
	string result = "";
	char c = read<char>(addr++);
	while (c) {
		result += c;
		c = read<char>(addr++);
	}
	return result;
}

uint64_t parse_perms(uint32_t perms) {
	uint64_t flags = 0;
	if (perms & PF_W)
		flags |= PDE64_RW;
	if (perms & PF_X)
		flags |= PDE64_NX;
	return flags;
}

void Mmu::load_elf(const vector<segment_t>& segments) {
	// This could be faster with a single PageWalker for each segment instead of
	// one for each alloc, write_mem and set_mem, but we're only doing this
	// once so who cares
	for (const segment_t& segm : segments) {
		if (segm.type != PT_LOAD)
			continue;
		dbgprintf("Loading at 0x%lx, len 0x%lx\n", segm.vaddr, segm.memsize);

		// Allocate memory region as user
		alloc(segm.vaddr, segm.memsize, parse_perms(segm.flags));

		// Write segment data into memory
		write_mem(segm.vaddr, segm.data, segm.filesize, false);

		// Fill padding, if any
		set_mem(segm.vaddr + segm.filesize, 0, segm.memsize - segm.filesize,
		        false);

		// Update brk beyond any segment we load
		m_brk = max(m_brk, (segm.vaddr + segm.memsize + 0xFFF) & ~0xFFF);
	}
	m_min_brk = m_brk;
}

void Mmu::dump_memory(psize_t len) const {
	ASSERT(len <= m_length, "Dump OOB: %ld/%ld", len, m_length);
	ofstream out("dump");
	out.write((char*)m_memory, len);
	out.close();
	cout << "Dumped " << len << " bytes of memory" << endl;
}