#include <iostream>
#include <pthread.h>
#include <fstream>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <string.h>
#include <stdexcept>
#include "mmu.h"
#include "page_walker.h"
#include "kvm_aux.h"

using namespace std;

// out 16, al; sysret
// const unsigned char SYSCALL_HANDLER[] = "\xe6\x10\x48\x0f\x07";

Mmu::Mmu(int vm_fd, size_t mem_size)
	: m_vm_fd(vm_fd)
	, m_memory((uint8_t*)mmap(NULL, mem_size, PROT_READ|PROT_WRITE,
	                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0))
	, m_length(mem_size)
	, m_ptl4((paddr_t*)(m_memory + PAGE_TABLE_PADDR))
	, m_next_page_alloc(PAGE_TABLE_PADDR + 0x1000)
	, m_next_mapping(MAPPINGS_START_ADDR)
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
	/* memcpy(
		m_memory + SYSCALL_HANDLER_ADDR,
		SYSCALL_HANDLER,
		sizeof(SYSCALL_HANDLER)
	); */

	//init_page_table();
}

Mmu::Mmu(int vm_fd, const Mmu& other)
	: Mmu(vm_fd, other.m_length)
{
	m_next_page_alloc = other.m_next_page_alloc;
	m_next_mapping    = other.m_next_mapping;
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
		alloc(next_page, new_brk - next_page, PDE64_RW | PDE64_USER);
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

	// Reset extra pages
	for (paddr_t paddr : m_dirty_extra) {
		memcpy(m_memory + paddr, other.m_memory + paddr, PAGE_SIZE);
	}

	// Clear bitmap and vector of extra pages
	memset(dirty.dirty_bitmap, 0, m_dirty_bits/8);
	m_dirty_extra.clear();

	// Reset state
	m_next_page_alloc = other.m_next_page_alloc;
	m_next_mapping    = other.m_next_mapping;
	m_brk             = other.m_brk;
	m_min_brk         = other.m_min_brk;

	/* if (memcmp(m_memory, other.m_memory, m_length) != 0) {
		printf("WOOPS reset is not working\n");
		for (size_t i = 0; i < m_dirty_bits; i++) {
			paddr = i*PAGE_SIZE;
			if (memcmp(m_memory + paddr, other.m_memory + paddr, PAGE_SIZE) != 0) {
				byte = m_dirty_bitmap[i/8];
				bit  = byte & (1 << (i%8));
				printf("page %ld at 0x%lx was not resetted, bit was %hhu!\n", i, paddr, bit);
			}
		}
		die(":(\n");
	} */
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
	flags |= PDE64_PRESENT;
	PageWalker pages(start, len, *this);
	do {
		pages.alloc_frame(flags);
	} while (pages.next());
}

vaddr_t Mmu::alloc(vsize_t len, uint64_t flags) {
	ASSERT((len & PTL1_MASK) == len, "alloc unaligned len");
	m_next_mapping -= len;
	alloc(m_next_mapping, len, flags);
	return m_next_mapping;
}

vaddr_t Mmu::alloc_stack(bool kernel) {
	// Allocate stack as writable and not executable
	vaddr_t  start;
	uint64_t flags = PDE64_RW | PDE64_NX;
	if (kernel) {
		start  = KERNEL_STACK_START_ADDR;
	} else {
		flags |= PDE64_USER;
		start  = STACK_START_ADDR;
	}
	alloc(start - STACK_SIZE, STACK_SIZE, flags);
	return start;
}

void Mmu::read_mem(void* dst, vaddr_t src, vsize_t len) {
	if (len == 0)
		return;

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
	if (len == 0)
		return;

	PageWalker pages(dst, len, *this);
	do {
		// Check write permissions, memcpy and mark page as dirty
		ASSERT(!chk_perms || (pages.flags() & PDE64_RW),
		       "writing to not writable page %lx", pages.vaddr());
		memcpy(
			m_memory + pages.paddr(),
			(uint8_t*)src + pages.offset(),
			pages.page_size()
		);
		m_dirty_extra.push_back(pages.paddr() & PTL1_MASK);
	} while (pages.next());
}

void Mmu::set_mem(vaddr_t addr, int c, vsize_t len, bool chk_perms) {
	if (len == 0)
		return;

	PageWalker pages(addr, len, *this);
	do {
		// Check write permissions, memset and mark page as dirty
		ASSERT(!chk_perms || (pages.flags() & PDE64_RW),
		       "memset to not writable page %lx", pages.vaddr());
		memset(m_memory + pages.paddr(), c, pages.page_size());
		m_dirty_extra.push_back(pages.paddr() & PTL1_MASK);
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

void Mmu::set_flags(vaddr_t addr, vsize_t len, uint64_t flags) {
	if (len == 0)
		return;

	PageWalker pages(addr, len, *this);
	do {
		// This will trigger ASSERT if page is not mapped
		pages.set_flags(flags);
	} while (pages.next());
}

uint64_t parse_perms(uint32_t perms) {
	uint64_t flags = 0;
	if (perms & PF_W)
		flags |= PDE64_RW;
	if (perms & PF_X)
		flags |= PDE64_NX;
	return flags;
}

void Mmu::load_elf(const vector<segment_t>& segments, bool kernel) {
	// This could be faster with a single PageWalker for each segment instead of
	// one for each alloc, write_mem and set_mem, but we're only doing this
	// once so who cares
	uint64_t flags;
	for (const segment_t& segm : segments) {
		if (segm.type != PT_LOAD)
			continue;
		dbgprintf("Loading at 0x%lx, len 0x%lx\n", segm.vaddr, segm.memsize);

		// Allocate memory region with given permissions
		flags = parse_perms(segm.flags);
		if (!kernel)
			flags |= PDE64_USER;
		alloc(segm.vaddr, segm.memsize, flags);

		// Write segment data into memory
		write_mem(segm.vaddr, segm.data, segm.filesize, false);

		// Fill padding, if any
		set_mem(segm.vaddr + segm.filesize, 0, segm.memsize - segm.filesize,
		        false);

		// In case this is not kernel, update brk beyond any segment we load
		if (!kernel)
			m_brk = max(m_brk, (segm.vaddr + segm.memsize + 0xFFF) & ~0xFFF);
	}
	if (!kernel)
		m_min_brk = m_brk;
}

void Mmu::dump_memory(psize_t len) const {
	ASSERT(len <= m_length, "Dump OOB: %ld/%ld", len, m_length);
	ofstream out("dump");
	out.write((char*)m_memory, len);
	out.close();
	cout << "Dumped " << len << " bytes of memory" << endl;
}