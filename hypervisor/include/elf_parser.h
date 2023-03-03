#ifndef _ELF_PARSER_H
#define _ELF_PARSER_H

#include <string>
#include <vector>
#include <elf.h>
#include "common.h"
#include "kvm_aux.h"
#include "elf_debug.h"

#define BITS 64

#if BITS == 32
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym  Elf32_Sym
#define Elf_Rela Elf32_Rela
#define Elf_Word Elf32_Word
#define Elf_Half Elf32_Half
#define Elf_Off  Elf32_Off
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#define ELFCLASS ELFCLASS32
#define R_JUMP_SLOT R_386_JMP_SLOT
#define EM EM_386
#define EM_S "EM_386"

#elif BITS == 64
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym  Elf64_Sym
#define Elf_Rela Elf64_Rela
#define Elf_Word Elf64_Word
#define Elf_Half Elf64_Half
#define Elf_Off  Elf64_Off
#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#define ELFCLASS ELFCLASS64
#define R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define EM EM_X86_64
#define EM_S "EM_X86_64"
#endif

struct phinfo_t {
    vaddr_t  e_phoff;      /* Program header table file offset */
    uint16_t e_phentsize;  /* Program header table entry size */
    uint16_t e_phnum;      /* Program header table entry count */
};

struct segment_t {
	uint32_t type;
	uint32_t flags;
	vaddr_t offset;
	vaddr_t vaddr;
	paddr_t paddr;
	vsize_t filesize;
	vsize_t memsize;
	vsize_t align;
	const void* data;
};

struct section_t {
	std::string name;
	uint32_t type;
	uint64_t flags;
	vaddr_t addr;
	vaddr_t offset;
	vsize_t size;
	uint32_t link;
	uint32_t info;
	vsize_t addralign;
	vsize_t entsize;
	const void* data;
};

struct symbol_t {
	std::string name;
	uint8_t type;
	uint8_t binding;
	uint8_t visibility;
	uint16_t shndx;
	vaddr_t value;
	vsize_t size;
};

struct relocation_t {
	std::string name;
	vaddr_t addr;
	uint32_t type;
};

class ElfParser {
	public:
		// Create an elf parser, loading file from disk. This object owns the
		// memory and is responsible of freeing it.
		ElfParser(const std::string& elf_path = "");

		// Create and elf parser, using data from memory. Caller owns the memory,
		// which should be alive while this object is alive. Elf path is still
		// needed for getting dependencies and loading associated debug elf if
		// specified.
		ElfParser(const std::string& elf_path, const uint8_t* data, size_t size);

		// Copy and move constructor, and destructor
		ElfParser(const ElfParser& other);
		ElfParser(ElfParser&& other);
		~ElfParser();

		friend void swap(ElfParser& first, ElfParser& second);
		ElfParser& operator=(ElfParser other);

		bool has_data() const;
		const uint8_t* data() const;
		vsize_t size() const;
		void set_load_addr(vaddr_t load_addr);
		vaddr_t load_addr() const;
		vaddr_t initial_brk() const;
		phinfo_t phinfo() const;
		bool is_pie() const;
		vaddr_t entry() const;
		std::string path() const;
		//std::string abs_path() const;
		std::string interpreter() const;
		std::vector<segment_t> segments() const;
		std::vector<section_t> sections() const;
		std::vector<symbol_t> symbols() const;
		//std::vector<relocation_t> relocations() const;
		std::pair<vaddr_t, vaddr_t> section_limits(const std::string& name) const;
		std::pair<vaddr_t, vaddr_t> symbol_limits(const std::string& name) const;
		std::string md5() const;

		// Get dynamic libraries dependencies using ldd
		std::vector<std::string> get_dependencies() const;

		vaddr_t resolve_symbol(const std::string& symbol_name) const;
		bool addr_to_symbol(vaddr_t addr, symbol_t& result) const;
		bool addr_to_symbol_str(vaddr_t addr, std::string& result) const;
		std::string addr_to_source(vaddr_t addr) const;
		std::vector<vaddr_t> get_stacktrace(const kvm_regs& kregs,
		                                    size_t num_frames, Mmu& mmu) const;

		static std::vector<std::pair<vaddr_t, const ElfParser*>> get_stacktrace(
			const std::vector<const ElfParser*>& elfs,
			const kvm_regs& kregs, size_t num_frames, Mmu& mmu
		);

	private:
		bool m_owns_data;
		const uint8_t* m_data;
		vsize_t m_size;

		// The load address of the binary, which is the lowest base address of
		// its loadable segments. For PIE binaries, it is 0 at first, and it
		// can be changed using `set_load_addr()`. For non-PIE binaries, it is
		// a fixed address (i.e. 0x400000) and it can not be changed.
		vaddr_t m_load_addr;

		// The initial brk address, which is the address of the next page after
		// the last loadable segments.
		vaddr_t m_initial_brk;

		phinfo_t m_phinfo;
		uint16_t m_type;
		vaddr_t m_entry;

		std::string m_path;
		std::string m_interpreter;
		std::vector<section_t> m_sections;
		std::vector<segment_t> m_segments;
		std::vector<symbol_t> m_symbols;
		std::vector<relocation_t> m_relocations;

		// Debug information of this binary
		ElfDebug m_debug;

		// Some binaries have the debug information in another binary, which we
		// call the debug elf. We are just interested in its symbols, which are
		// moved to ours, and its debug info.
		ElfParser* m_debug_elf;

		void load_file();
		void init();
};

#endif