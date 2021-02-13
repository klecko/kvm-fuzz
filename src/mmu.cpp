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

Mmu::Mmu(int vm_fd, size_t mem_size)
	: vm_fd(vm_fd)
	, memory((uint8_t*)mmap(NULL, mem_size, PROT_READ|PROT_WRITE,
	                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0))
	, memory_len(mem_size)
	, ptl4((paddr_t*)(memory + PAGE_TABLE_PADDR))
	, next_page_alloc(PAGE_TABLE_PADDR + 0x1000)
	, dirty_bits(memory_len/PAGE_SIZE)
	, dirty_bitmap(new uint8_t[dirty_bits/8])
	, brk(0)
	, min_brk(0)
{
	ERROR_ON(memory == MAP_FAILED, "mmap mmu memory");

	madvise(memory, memory_len, MADV_MERGEABLE);

	memset(dirty_bitmap, 0, dirty_bits/8);

	struct kvm_userspace_memory_region memreg = {
		.slot = 0,
		.flags = KVM_MEM_LOG_DIRTY_PAGES,
		.guest_phys_addr = 0,
		.memory_size = mem_size,
		.userspace_addr = (unsigned long)memory
	};
	ioctl_chk(vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg);

	// Set syscall handler
	memcpy(memory + SYSCALL_HANDLER_ADDR, SYSCALL_HANDLER, sizeof(SYSCALL_HANDLER));

	init_page_table();
}

/* Mmu::Mmu(int vm_fd, const Mmu& other)
	: vm_fd(vm_fd)
	, memory((uint8_t*)mmap(NULL, other.memory_len, PROT_READ|PROT_WRITE,
	                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0))
	, memory_len(other.memory_len)
	, ptl4((paddr_t*)(memory + PAGE_TABLE_PADDR))
	, next_page_alloc(other.next_page_alloc)
	, dirty_bits(memory_len/PAGE_SIZE)
	, dirty_bitmap(new uint8_t[dirty_bits/8])
	, brk(other.brk)
	, min_brk(other.min_brk)
{
	memcpy(memory, other.memory, memory_len);
	memcpy(dirty_bitmap, other.dirty_bitmap, dirty_bits/8);
} */
Mmu::Mmu(int vm_fd, const Mmu& other)
	: Mmu(vm_fd, other.memory_len)
{
	next_page_alloc = other.next_page_alloc;
	brk             = other.brk;
	min_brk         = other.min_brk;
	memcpy(memory, other.memory, memory_len);

	// Reset kvm dirty bitmap
	memset(dirty_bitmap, 0xFF, dirty_bits/8);
	kvm_clear_dirty_log clear_dirty = {
		.slot = 0,
		.num_pages = dirty_bits,
		.first_page = 0,
		.dirty_bitmap = dirty_bitmap,
	};
	ioctl_chk(vm_fd, KVM_CLEAR_DIRTY_LOG, &clear_dirty);
	memset(dirty_bitmap, 0, dirty_bits/8);
}

void Mmu::reset(const Mmu& other) {
	// Get dirty pages bitmap
	size_t bits = memory_len/PAGE_SIZE;
	kvm_dirty_log dirty = {
		.slot = 0,
		.dirty_bitmap = dirty_bitmap
	};
	ioctl_chk(vm_fd, KVM_GET_DIRTY_LOG, &dirty);

	// Reset pages
	uint8_t byte, bit;
	paddr_t paddr;
	for (size_t i = 0; i < bits; i++) {
		byte = dirty_bitmap[i/8];
		bit = byte & (1 << (i%8));
		if (bit) {
			paddr = i*PAGE_SIZE;
			memcpy(memory + paddr, other.memory + paddr, PAGE_SIZE);
		}
	}

	// Reset bitmap
	memset(dirty.dirty_bitmap, 0, bits/8);
}

psize_t Mmu::size() const {
	return memory_len;
}

paddr_t Mmu::alloc_frame() {
	ASSERT(next_page_alloc <= memory_len - PAGE_SIZE, "OOM");
	paddr_t ret = next_page_alloc;
	next_page_alloc += PAGE_SIZE;
	return ret;
}

paddr_t* Mmu::get_pte(vaddr_t vaddr) {
	// Go over the page table, allocating entries when needed
	int flags = PDE64_PRESENT | PDE64_RW | PDE64_USER;

	int ptl4_i = PTL4_INDEX(vaddr);
	if (!ptl4[ptl4_i]) {
		ptl4[ptl4_i] = alloc_frame() | flags;
	}

	paddr_t* ptl3 = (paddr_t*)(memory + (ptl4[ptl4_i] & PTL1_MASK));
	int ptl3_i = PTL3_INDEX(vaddr);
	if (!ptl3[ptl3_i]) {
		ptl3[ptl3_i] = alloc_frame() | flags;
	}

	paddr_t* ptl2 = (paddr_t*)(memory + (ptl3[ptl3_i] & PTL1_MASK));
	int ptl2_i = PTL2_INDEX(vaddr);
	if (!ptl2[ptl2_i]) {
		ptl2[ptl2_i] = alloc_frame() | flags;
	}

	paddr_t* ptl1 = (paddr_t*)(memory + (ptl2[ptl2_i] & PTL1_MASK));
	int ptl1_i = PTL1_INDEX(vaddr);
	return &ptl1[ptl1_i];
}

paddr_t Mmu::virt_to_phys(vaddr_t vaddr) {
	paddr_t* pte = get_pte(vaddr);
	ASSERT(*pte, "Trying to translate not mapped virtual address: 0x%lx", vaddr);
	return (*pte & PTL1_MASK) + PAGE_OFFSET(vaddr);
}

void Mmu::alloc(vaddr_t start, vsize_t len, uint64_t flags) {
	// Normalize args
	flags |= PDE64_PRESENT | PDE64_USER;
	if (PAGE_OFFSET(start)) {
		len += PAGE_OFFSET(start);
		start &= PTL1_MASK;
	}
	if (PAGE_OFFSET(len)) {
		len = (len + 0xFFF) & PTL1_MASK;
	}

	paddr_t* pte;
	for (vaddr_t vaddr = start; vaddr < start + len; vaddr += PAGE_SIZE) {
		pte = get_pte(vaddr);
		if (!*pte)
			*pte = alloc_frame() | flags;
		else
			ASSERT((*pte & ~PTL1_MASK) == flags, "page was already mapped with "
			       "different flags");

		dbgprintf("Alloc frame: 0x%lx mapped to 0x%lx\n", vaddr, *pte & PTL1_MASK);
	}
}

vaddr_t Mmu::get_brk() {
	return brk;
}

bool Mmu::set_brk(vaddr_t new_brk) {
	dbgprintf("trying to set brk to %lX\n", new_brk);
	if (new_brk < min_brk)
		return false;

	// Allocate space if needed
	if (new_brk >= brk)
		alloc(brk, new_brk - brk, PDE64_RW);

	dbgprintf("brk set to %lX\n", new_brk);
	brk = new_brk;
	return true;
}

void Mmu::read_mem(void* dst, vaddr_t src, vsize_t len) {
	vsize_t offset = 0, size;
	paddr_t paddr;
	while (offset < len) {
		// Read memory by pages. Each iteration, copy until the end of the page
		// or until the end of dst.
		size = min(PAGE_SIZE - PAGE_OFFSET(src + offset), len - offset);
		paddr = virt_to_phys(src + offset);
		memcpy((uint8_t*)dst + offset, memory + paddr, size);
		offset += size;
	}
}

void Mmu::write_mem(vaddr_t dst, const void* src, vsize_t len){
	vsize_t offset = 0, size;
	paddr_t paddr;
	while (offset < len) {
		// Copy memory by pages. Each iteration, copy until the end of the page
		// or until the end of src.
		size = min(PAGE_SIZE - PAGE_OFFSET(dst + offset), len - offset);
		paddr = virt_to_phys(dst + offset);
		memcpy(memory + paddr, (const uint8_t*)src + offset, size);
		offset += size;
	}
}

void Mmu::set_mem(vaddr_t addr, int c, vsize_t len){
	vsize_t offset = 0, size;
	paddr_t paddr;
	while (offset < len) {
		// Set memory by pages. Each iteration, set until the end of the page
		// or until the end of the memory we want to set.
		size = min(PAGE_SIZE - PAGE_OFFSET(addr + offset), len - offset);
		paddr = virt_to_phys(addr + offset);
		memset(memory + paddr, c, size);
		offset += size;
	}
}

void Mmu::init_page_table() {
	// Identity map the first 4K, as writable without PDE64_USER
	paddr_t* pte = get_pte(0);
	*pte = 0 | PDE64_PRESENT | PDE64_RW;
}

uint64_t parse_perms(const string& perms) {
	uint64_t flags = 0;
	if (perms.find("W") != string::npos)
		flags |= PDE64_RW;
	if (perms.find("E") == string::npos)
		flags |= PDE64_NX;
	return flags;
}

void Mmu::load_elf(const vector<segment_t>& segments) {
	for (const segment_t& segm : segments) {
		if (segm.type != "LOAD")
			continue;
		dbgprintf("Loading at 0x%lx, len 0x%lx\n", segm.virtaddr, segm.memsize);

		// Allocate memory region as user
		alloc(segm.virtaddr, segm.memsize, parse_perms(segm.flags));

		// Write segment data into memory
		write_mem(segm.virtaddr, segm.data, segm.filesize);

		// Fill padding, if any
		set_mem(segm.virtaddr + segm.filesize, 0, segm.memsize - segm.filesize);

		// Update brk beyond any segment we load
		brk = max(brk, (segm.virtaddr + segm.memsize + 0xFFF) & ~0xFFF);
	}
	min_brk = brk;
}

uint8_t* Mmu::get(vaddr_t guest) {
	return memory + virt_to_phys(guest);
}

void Mmu::dump_memory(psize_t len) const {
	ofstream out("dump");
	assert(len <= memory_len);
	out.write((char*)memory, len);
	out.close();
	cout << "Dumped " << len << " bytes of memory" << endl;
}