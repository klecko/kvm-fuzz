#ifndef _MMU_H
#define _MMU_H

#include <vector>
#include "elf_parser.h"
#include "common.h"

class Mmu {
public:
	static const paddr_t PAGE_TABLE_PADDR     = 0x1000;
	static const paddr_t SYSCALL_HANDLER_ADDR = 0x0;      // both paddr and vaddr
	static const vaddr_t ELF_ADDR             = 0x400000; // base for DYN ELF
	static const vaddr_t STACK_START_ADDR     = 0x800000000000;
	static const vsize_t STACK_SIZE           = 0x10000;
	static const vaddr_t MAPPINGS_START_ADDR  = 0x7ffff7ffe000;

	// Normal constructor
	Mmu(int vm_fd, size_t mem_size);

	// Copy constructor: create a Mmu identical to `other` and associated to
	// `vm_fd`. This allows using the method `reset`
	Mmu(int vm_fd, const Mmu& other);

	~Mmu();

	// Creating a Mmu without providing vm_fd doesn't make sense
	Mmu(const Mmu&) = delete;
	Mmu& operator=(const Mmu&) = delete;

	// Getters and setters. Brk setter returns whether the change was successful
	psize_t size() const;
	vaddr_t brk() const;
	bool set_brk(vaddr_t new_brk);

	// Reset to the state in `other`, given that current Mmu has been
	// constructed as a copy of `other`
	void reset(const Mmu& other);

	// Allocate a physical page
	paddr_t alloc_frame();

	// Get page table entry of given virtual address, performing a page walk and
	// allocating entries if needed. This is a wrapper for PageWalker. If needed
	// for a range, use PageWalker instead
	paddr_t* get_pte(vaddr_t vaddr);

	// Translate a virtual address to a physical address. Same as in `get_pte`
	// applies here
	paddr_t virt_to_phys(vaddr_t vaddr);

	// Guest to host address conversion
	uint8_t* get(vaddr_t guest);

	// Allocate given userspace virtual memory region
	void alloc(vaddr_t start, vsize_t len, uint64_t flags);

	// Allocate the stack and return its address
	vaddr_t alloc_stack();

	// Basic memory modification primitives
	void read_mem(void* dst, vaddr_t src, vsize_t len);
	void write_mem(vaddr_t dst, const void* src, vsize_t len,
	               bool check_perms = true);
	void set_mem(vaddr_t addr, int c, vsize_t len, bool check_perms = true);

	// Read and write arbitrary data types to guest memory
	template<class T>
	T read(vaddr_t addr);

	template <class T>
	void write(vaddr_t addr, T value);

	// Read a null-terminated string from `addr`
	std::string read_string(vaddr_t addr);

	// Load elf into memory, updating brk
	void load_elf(const std::vector<segment_t>& segments);

	void dump_memory(psize_t len) const;

private:
	// Auxiliary class to walk the page table
	friend class PageWalker;
	class PageWalker {
	public:
		PageWalker(vaddr_t vaddr, Mmu& mmu);

		// Range page walker
		PageWalker(vaddr_t start, vsize_t len, Mmu& mmu);

		vaddr_t  start();
		vsize_t  len();
		paddr_t* pte();

		// Current virtual address (virtual address of current page, with
		// offset in case it is the first one)
		vaddr_t vaddr();

		// Current physichal address (physichal address of current page, with
		// offset in case it's the first one)
		paddr_t paddr();

		// Offset from the beginning to current virtual address
		vsize_t offset();

		// Memory length from current address until the end of the page, or
		// until the end of range if it's the last page of a range page walker
		vsize_t page_size();

		// Get and set current page flags
		uint64_t flags();
		void set_flags(uint64_t flags);

		// Alloc a frame for current page. Fail if it has already a frame
		void alloc_frame(uint64_t flags);

		// Advance to the next page. In case of range page walkers, returns
		// whether the new page is in given range. Normal page walkers always
		// return false
		bool next();

	private:
		static const int FLAGS;
		vaddr_t  m_start;
		vsize_t  m_len;
		Mmu&     m_mmu;
		vsize_t  m_offset;
		paddr_t* m_ptl3;
		paddr_t* m_ptl2;
		paddr_t* m_ptl1;
		uint64_t m_ptl4_i;
		uint64_t m_ptl3_i;
		uint64_t m_ptl2_i;
		uint64_t m_ptl1_i;

		void update_ptl3();
		void update_ptl2();
		void update_ptl1();
		void next_ptl4_entry();
		void next_ptl3_entry();
		void next_ptl2_entry();
		void next_ptl1_entry();
	};

	int m_vm_fd;

	// Guest physical memory
	uint8_t* m_memory;
	size_t   m_length;

	// Pointer to page table level 4
	// (at physical address PAGE_TABLE_PADDR)
	paddr_t* m_ptl4;

	// Physical address of the next page allocated
	paddr_t  m_next_page_alloc;

	uint32_t m_dirty_bits;
	uint8_t* m_dirty_bitmap;

	// Brk
	vaddr_t  m_brk, m_min_brk;

	void init_page_table();
};

template<class T>
T Mmu::read(vaddr_t addr) {
	T result;
	read_mem(&result, addr, sizeof(T));
	return result;
}

template<class T>
void Mmu::write(vaddr_t addr, T value) {
	write_mem(addr, &value, sizeof(T));
}
#endif