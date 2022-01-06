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
		ElfDebug();
		ElfDebug(const uint8_t* data, size_t size);

		bool has() const;
		bool next_frame(vaddr_t regs[DwarfReg::MAX], Mmu& mmu) const;
		std::string addr_to_source(vaddr_t addr) const;

	private:
		bool m_has_dwarf;
		dwarf_elf_handle m_dwarf_elf;
		Dwarf_Debug m_dwarf;
		Dwarf_Cie* m_dwarf_cie_data;
		Dwarf_Fde* m_dwarf_fde_data;
		Dwarf_Signed m_dwarf_cie_count;
		Dwarf_Signed m_dwarf_fde_count;

		bool get_current_frame_regs_info(vaddr_t instruction_pointer,
		                                 Dwarf_Regtable3* regtable) const;

		bool die_has_pc(Dwarf_Die die, Dwarf_Addr pc) const;

		std::string get_source_str_cu_die(Dwarf_Die cu_die, Dwarf_Addr pc) const;
		std::string get_source_str_from_line(Dwarf_Line line) const;
};

#endif
