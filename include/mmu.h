#ifndef _MMU_H
#define _MMU_H

#include <vector>
#include "elf_parser.hpp"
#include "common.h"

class Mmu {
public:
	static const paddr_t PAGE_TABLE_PADDR = 0x1000;
	static const paddr_t SYSCALL_HANDLER_ADDR = 0x0; // both paddr and vaddr
	Mmu(int vm_fd, size_t mem_size);
	Mmu(int vm_fd, const Mmu& other);

	void reset(const Mmu& other);

	psize_t size() const;
	void load_elf(const std::vector<segment_t>& segments);
	uint8_t* get(vaddr_t guest);
	void dump_memory(psize_t len) const;

	// Allocate a physical page
	paddr_t alloc_frame();

	// Get page table entry of given virtual address, performing a page walk and
	// allocating entries if needed
	paddr_t* get_pte(vaddr_t vaddr);

	// Allocate and map given userspace virtual memory region to physical memory
	void alloc(vaddr_t start, vsize_t len, uint64_t flags);

	// Translate a virtual address to a physical address
	paddr_t virt_to_phys(vaddr_t vaddr);

	// Get brk
	vaddr_t get_brk();

	// Set brk. Returns true if change was successful, false otherwise.
	bool set_brk(vaddr_t new_brk);

	void read_mem(void* dst, vaddr_t src, vsize_t len);
	void write_mem(vaddr_t dst, const void* src, vsize_t len);
	void set_mem(vaddr_t addr, int c, vsize_t len);

	template<class T>
	T read(vaddr_t addr);

	template <class T>
	void write(vaddr_t addr, T value);

private:
	int vm_fd;

	// Guest physical memory
	uint8_t* memory;
	size_t   memory_len;

	// Pointer to page table level 4
	// (at physical address PAGE_TABLE_PADDR)
	paddr_t* ptl4;

	// Physical address of the next page allocated
	paddr_t next_page_alloc;

	uint32_t dirty_bits;
	uint8_t* dirty_bitmap;

	// Brk
	vaddr_t brk, min_brk;

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