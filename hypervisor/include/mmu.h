#ifndef _MMU_H
#define _MMU_H

#include <vector>
#include "elf_parser.h"
#include "common.h"
#include "kvm_aux.h"

class Mmu {
public:
	inline uint8_t* memory() const { return m_memory; }
	static const paddr_t PAGE_TABLE_PADDR        = 0x1000;
	static const vaddr_t ELF_ADDR                = 0x400000; // base for DYN ELF
	static const vaddr_t KERNEL_STACK_START_ADDR = 0xFFFFFFFFFFFFF000;
	static const vsize_t STACK_SIZE              = 0x10000;
	static const vaddr_t PHYSMAP_ADDR            = 0xFFFFFF8000000000;
	static const vaddr_t INTERPRETER_ADDR        = 0x400000000000;

	// Normal constructor
	Mmu(int vm_fd, int vcpu_fd, size_t mem_size);

	// Copy constructor: create a Mmu identical to `other` and associated to
	// given vm and vcpu. This allows using the method `reset`
	Mmu(int vm_fd, int vcpu_fd, const Mmu& other);

	~Mmu();

	// Creating a Mmu without providing vm_fd doesn't make sense
	Mmu(const Mmu&) = delete;
	Mmu& operator=(const Mmu&) = delete;

	// Getters and setters
	psize_t size() const;
	paddr_t next_frame_alloc() const;
	void disable_allocations();

	// Reset to the state in `other`, given that current Mmu has been
	// constructed as a copy of `other`. Returns the number of pages resetted
	size_t reset(const Mmu& other);

	// Allocate a physical page
	paddr_t alloc_frame();

	// Get page table entry value of given virtual address, performing a page
	// walk and allocating entries if needed. This is a wrapper for PageWalker.
	// If needed for a range, use PageWalker instead
	paddr_t get_pte_val(vaddr_t vaddr);

	// Translate a virtual address to a physical address. Same as in `get_pte`
	// applies here
	paddr_t virt_to_phys(vaddr_t vaddr);

	// Guest to host address conversion
	uint8_t* get(vaddr_t guest);

	// Allocate given virtual memory region
	void alloc(vaddr_t start, vsize_t len, uint64_t flags);

	// Allocate a stack and return its address
	vaddr_t alloc_kernel_stack();

	// Basic memory modification primitives
	void read_mem(void* dst, vaddr_t src, vsize_t len);
	void write_mem(vaddr_t dst, const void* src, vsize_t len,
	               bool check_perms = true);
	void set_mem(vaddr_t addr, int c, vsize_t len, bool check_perms = true);

	// Read and write arbitrary data types to guest memory
	template<class T>
	T read(vaddr_t addr);

	template <class T>
	void write(vaddr_t addr, const T& value, bool check_perms = true);

	template<class T>
	T readp(paddr_t addr);

	template <class T>
	void writep(paddr_t addr, const T& value);

	// Read a null-terminated string from `addr`
	std::string read_string(vaddr_t addr);

	// Set flags to given memory region in the page table
	void set_flags(vaddr_t addr, vsize_t len, uint64_t flags);

	// Load elf into memory
	void load_elf(const std::vector<segment_t>& segments, bool kernel);

	void dump_memory(psize_t len) const;

private:
	// Auxiliary class to walk the page table
	friend class PageWalker;
	class PageWalker;

	int m_vm_fd;
	int m_vcpu_fd;

	// Guest physical memory
	uint8_t* m_memory;
	size_t   m_length;

	// Pointer to page table level 4
	// (at physical address PAGE_TABLE_PADDR)
	paddr_t  m_ptl4;

	// True if guest kernel hasn't taken control of the memory yet
	bool     m_can_alloc;

	// Physical address of the next page allocated
	paddr_t  m_next_page_alloc;

#ifdef ENABLE_KVM_DIRTY_LOG_RING
	size_t m_dirty_ring_i;
	size_t m_dirty_ring_entries;
	kvm_dirty_gfn* m_dirty_ring;
#else
	uint32_t m_dirty_bits;
	uint8_t* m_dirty_bitmap;
#endif

	// Addresses of dirty pages, appart from the ones indicated by
	// the dirty bitmap. When we write to guest, kvm bitmap is not updated
	// and there doesn't seem to be a way to update it. For now, those pages
	// are saved here.
	std::vector<paddr_t> m_dirty_extra;

	void init_page_table();
};

template<class T>
T Mmu::read(vaddr_t addr) {
	T result;
	read_mem(&result, addr, sizeof(T));
	return result;
}

template<class T>
void Mmu::write(vaddr_t addr, const T& value, bool check_perms) {
	write_mem(addr, &value, sizeof(T), check_perms);
}

template<class T>
T Mmu::readp(paddr_t addr) {
	ASSERT(addr + sizeof(T) <= m_length, "OOB: 0x%lx", addr);
	T value;
	memcpy(&value, m_memory + addr, sizeof(T));
	return value;
}

template <class T>
void Mmu::writep(paddr_t addr, const T& value) {
	ASSERT(addr + sizeof(T) <= m_length, "OOB: 0x%lx", addr);
	memcpy(m_memory + addr, &value, sizeof(value));

	// Set region as dirty
	paddr_t p = addr;
	while (p < addr + sizeof(T)) {
		m_dirty_extra.push_back(addr & PTL1_MASK);
		p += PAGE_SIZE - PAGE_OFFSET(p);
	}
}
#endif