#ifndef _ELF_DEBUG_H
#define _ELF_DEBUG_H

#include <libdwarf/libdwarf.h>
#include <vector>
#include "common.h"

class Mmu;

// https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf
// figure 3.38: DWARF Register Numer Mapping
enum DwarfReg {
	Rax, Rdx, Rcx, Rbx,
	Rsi, Rdi, Rbp, Rsp,
	R8, R9, R10, R11,
	R12, R13, R14, R15,
	ReturnAddress,
	MAX
};

class ElfDebug {
	public:
		// Default constructor. No debug info associated.
		ElfDebug();

		// Get DWARF information from given ELF. Caller is the owner of the
		// memory, which must live while this object lives.
		ElfDebug(const uint8_t* data, size_t size);

		// We do not provide copy constructor, because libdwarf hasn't any easy
		// way to do that. In order to perform a copy, use the constructor, or
		// the move constructor if possible.
		ElfDebug(const ElfDebug& other) = delete;
		ElfDebug(ElfDebug&& other);

		// Destructor
		~ElfDebug();

		friend void swap(ElfDebug& first, ElfDebug& second);

		// Same as copy constructor, we only provide assignment operator from
		// rvalue.
		ElfDebug& operator=(const ElfDebug& other) = delete;
		ElfDebug& operator=(ElfDebug&& other);

		// Returns whether there's debug info available or not
		bool has() const;

		// Returns whether there's debug info for stack frames available or not
		bool has_frames() const;

		// Given the registers at a given frame, updates them to the values
		// they had the previous frame. Returns whether it was successful or not.
		bool next_frame(vaddr_t regs[DwarfReg::MAX], Mmu& mmu) const;

		// Returns the source file and line associated with given virtual address.
		// Returned string can be empty if it couldn't be retrieved.
		std::string addr_to_source(vaddr_t addr) const;

	private:
		dwarf_elf_handle m_elf;
		Dwarf_Debug m_dwarf;
		Dwarf_Cie* m_cie_data;
		Dwarf_Fde* m_fde_data;
		Dwarf_Signed m_cie_count;
		Dwarf_Signed m_fde_count;

		// Get the information about where are the registers of the previous
		// frame located.
		bool get_current_frame_regs_info(vaddr_t instruction_pointer,
		                                 Dwarf_Regtable3* regtable) const;

		// Returns whether given pc is inside given die.
		bool die_has_pc(Dwarf_Die die, Dwarf_Addr pc) const;

		// Get the source string associated to pc from give cu die.
		std::string get_source_str_cu_die(Dwarf_Die cu_die, Dwarf_Addr pc) const;

		// Get the source string associated to given line.
		std::string get_source_str_from_line(Dwarf_Line line) const;

		// Not used for now, as symbols are obtained without DWARF info.
		std::string get_symbol_cu_die(Dwarf_Die cu_die, Dwarf_Addr pc) const;
};

#endif
