#include <libelf.h>
#include <iostream>
#include <dwarf.h>
#include "mmu.h"
#include "elf_debug.h"
#include "common.h"

using namespace std;

// If this errmsg produces "Dwarf_Error is NULL", that's because ret is DW_DLV_NO_ENTRY
#define DWARF_CHECK(ret, err) ASSERT(ret == DW_DLV_OK, "%s", dwarf_errmsg(err))

ElfDebug::ElfDebug() : m_has_dwarf(false) {}

ElfDebug::ElfDebug(const uint8_t* data, size_t size) {
	// TODO: This is leaky, and unsafe when this object is copied

	// Get libdwarf handler from memory-loaded elf
	Dwarf_Error err = nullptr;
	int ret;
	m_dwarf_elf = elf_memory((char*)data, size);
	ASSERT(m_dwarf_elf, "error reading elf from memory");
	ret = dwarf_elf_init(m_dwarf_elf, DW_DLC_READ, nullptr, nullptr,
						 &m_dwarf, &err);
	if (ret == DW_DLV_NO_ENTRY) {
		m_has_dwarf = false;
		return;
	}
	DWARF_CHECK(ret, err);

	// Get data
	ret = dwarf_get_fde_list_eh(m_dwarf, &m_dwarf_cie_data, &m_dwarf_cie_count,
		&m_dwarf_fde_data, &m_dwarf_fde_count, &err);
	if (ret == DW_DLV_NO_ENTRY) {
		ret = dwarf_get_fde_list(m_dwarf, &m_dwarf_cie_data, &m_dwarf_cie_count,
			&m_dwarf_fde_data, &m_dwarf_fde_count, &err);
	}
	m_has_dwarf = (ret == DW_DLV_OK);
}

bool ElfDebug::has() const {
	return m_has_dwarf;
}

bool ElfDebug::next_frame(vaddr_t regs[DwarfReg::MAX], Mmu& mmu) const {
	if (!m_has_dwarf)
		return false;

	// Allocate register table
	Dwarf_Regtable3 regtable;
	regtable.rt3_reg_table_size = DW_REG_TABLE_SIZE;
	regtable.rt3_rules = (Dwarf_Regtable_Entry3_s*)alloca(
		sizeof(Dwarf_Regtable_Entry3_s)*DW_REG_TABLE_SIZE
	);

	// Get register information. Some functions like malloc_printerr end
	// with a call (noreturn), so the return address is out of bounds of
	// the function. We substract one from the return address to avoid this.
	if (!get_current_frame_regs_info(regs[DwarfReg::ReturnAddress]-1, &regtable))
		return false;

	// If return address value is undefined, we've finished
	auto ra_value = regtable.rt3_rules[DwarfReg::ReturnAddress].dw_regnum;
	if (ra_value == DW_FRAME_UNDEFINED_VAL)
		return false;

	// First update CFA register (RSP), which is always the value of a
	// register (usually the old RSP, but not always; this is why we have
	// to restore every register and not just RSP) plus an offset
	ASSERT(regtable.rt3_cfa_rule.dw_regnum < DwarfReg::MAX, "oob reg: %d",
		   regtable.rt3_cfa_rule.dw_regnum);
	ASSERT(regtable.rt3_cfa_rule.dw_offset_relevant != 0,
		   "woops, CFA offset not relevant");
	DwarfReg regnum = (DwarfReg)regtable.rt3_cfa_rule.dw_regnum;
	regs[DwarfReg::Rsp] =
		regs[regnum] + regtable.rt3_cfa_rule.dw_offset_or_block_len;

	// Update every other register
	for (int i = 0; i < regtable.rt3_reg_table_size; i++) {
		Dwarf_Regtable_Entry3_s& rule = regtable.rt3_rules[i];
		if (rule.dw_regnum == DW_FRAME_SAME_VAL ||
			rule.dw_regnum == DW_FRAME_UNDEFINED_VAL)
			continue;
		ASSERT(i < DwarfReg::MAX, "oob reg %d", i);

		// Get register value
		vaddr_t value, addr;
		if (rule.dw_value_type == DW_EXPR_OFFSET) {
			if (rule.dw_offset_relevant) {
				// Value is stored at the address CFA + N
				addr = regs[DwarfReg::Rsp] + rule.dw_offset_or_block_len;
				value = mmu.read<vsize_t>(addr);
			} else {
				// Value is the value of the register dw_regnum
				ASSERT(rule.dw_regnum < DwarfReg::MAX, "oob reg %d",
						rule.dw_regnum);
				value = regs[rule.dw_regnum];
				TODO
			}
		} else if (rule.dw_value_type == DW_EXPR_VAL_OFFSET) {
			// Value is CFA + N
			value = regs[DwarfReg::Rsp] + rule.dw_offset_or_block_len;
			TODO
		} else TODO

		// Update register value
		regs[i] = value;
	}

	return true;
}


bool ElfDebug::get_current_frame_regs_info(vaddr_t instruction_pointer,
                                           Dwarf_Regtable3* regtable) const
{
	if (!m_has_dwarf)
		return false;

	// Get Frame Description Entry for instruction pointer
	Dwarf_Error err = nullptr;
	Dwarf_Fde fde;
	int ret = dwarf_get_fde_at_pc(m_dwarf_fde_data, instruction_pointer, &fde,
		nullptr, nullptr, &err);
	if (ret != DW_DLV_OK)
		return false;

	// Get regs information
	Dwarf_Addr row_pc;
	ret = dwarf_get_fde_info_for_all_regs3(fde, instruction_pointer, regtable,
		&row_pc, &err);
	return ret == DW_DLV_OK;
}


// cu: compilation unit
// die: debugging information entry

// https://github.com/Crablicious/libdwarf-addr2line/blob/master/addr2line.c
// https://github.com/awslabs/aws-lambda-cpp/blob/master/src/backward.h#L2453
// https://gist.github.com/tuxology/6144170

Dwarf_Bool is_info = true; // no idea what this is for

// Attempt to get the limits of a given DIE querying attributes lowpc and highpc
bool get_die_limits(Dwarf_Die die, Dwarf_Addr* low_pc, Dwarf_Addr* high_pc) {
	if (dwarf_lowpc(die, low_pc, nullptr) != DW_DLV_OK)
		return false;

	Dwarf_Half return_form;
	Dwarf_Form_Class return_class;
	if (dwarf_highpc_b(die, high_pc, &return_form, &return_class, nullptr) != DW_DLV_OK)
		return false;

	switch (return_class) {
		case Dwarf_Form_Class::DW_FORM_CLASS_CONSTANT:
			*high_pc += *low_pc;
			break;
		case Dwarf_Form_Class::DW_FORM_CLASS_ADDRESS:
			break;
		default:
			const char* class_name = nullptr;
			dwarf_get_FORM_CLASS_name(return_class, &class_name);
			ASSERT(false, "TODO return class: '%s'", class_name);
	}

	return true;
}

string ElfDebug::addr_to_source(vaddr_t pc) const {
	string result;
	Dwarf_Unsigned next_cu_header;
	Dwarf_Half header_cu_type;
	bool found = false;
	Dwarf_Error err;

	// Iterate compilation unit headers
	while (dwarf_next_cu_header_d(
		m_dwarf, is_info, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
		nullptr, nullptr, &next_cu_header, &header_cu_type, &err
	) == DW_DLV_OK && !found) {
		// Get the cu die
		Dwarf_Die cu_die = 0;
		if (dwarf_siblingof_b(m_dwarf, 0, is_info, &cu_die, nullptr) != DW_DLV_OK)
			continue;

		// Check if pc belongs to this cu, and get the source string in that case
		if (die_has_pc(cu_die, pc)) {
			result = get_source_str_cu_die(cu_die, pc);
			found = true;
		}

		dwarf_dealloc(m_dwarf, cu_die, DW_DLA_DIE);
	}

	while (dwarf_next_cu_header_d(
		m_dwarf, is_info, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
		nullptr, nullptr, &next_cu_header, &header_cu_type, &err
	) == DW_DLV_OK) {}
	return result;
}

bool ElfDebug::die_has_pc(Dwarf_Die die, Dwarf_Addr pc) const {
	// Attempt to get limits with highpc, lowpc
	Dwarf_Addr low_pc = DW_DLV_BADADDR, high_pc = DW_DLV_BADADDR;
	if (get_die_limits(die, &low_pc, &high_pc)) {
		return low_pc <= pc && pc < high_pc;
	}

	// We might have gotten the low_pc despite having failed later with the
	// high_pc. Check if DW_AT_ranges attribute is present and search for the
	// PC in the returned ranges list.
	// I have no idea what's going on here
	bool result = false;
	Dwarf_Attribute attr;
	if (dwarf_attr(die, DW_AT_ranges, &attr, NULL) != DW_DLV_OK)
		return result;

	Dwarf_Unsigned offset;
	if (dwarf_global_formref(attr, &offset, NULL) == DW_DLV_OK) {
		Dwarf_Signed count = 0;
		Dwarf_Ranges *ranges = 0;
		Dwarf_Addr baseaddr = (low_pc != DW_DLV_BADADDR ? low_pc : 0);
		if (dwarf_get_ranges_a(m_dwarf, offset, die, &ranges, &count, NULL, NULL) == DW_DLV_OK) {
			for (int i = 0; i < count; i++) {
				Dwarf_Ranges *cur = ranges + i;
				if (cur->dwr_type == DW_RANGES_ENTRY) {
					Dwarf_Addr rng_lowpc, rng_highpc;
					rng_lowpc = baseaddr + cur->dwr_addr1;
					rng_highpc = baseaddr + cur->dwr_addr2;
					if (pc >= rng_lowpc && pc < rng_highpc) {
						result = true;
						break;
					}
				} else if (cur->dwr_type == DW_RANGES_ADDRESS_SELECTION) {
					baseaddr = cur->dwr_addr2;
				} else {  // DW_RANGES_END
					baseaddr = low_pc;
				}
			}
			dwarf_ranges_dealloc(m_dwarf, ranges, count);
		}
	}
	dwarf_dealloc(m_dwarf, attr, DW_DLA_ATTR);
	return result;
}


string ElfDebug::get_source_str_cu_die(Dwarf_Die cu_die, Dwarf_Addr pc) const {
	string result;
	Dwarf_Unsigned version;
	Dwarf_Small table_count;
	Dwarf_Line_Context ctxt;
	if (dwarf_srclines_b(cu_die, &version, &table_count, &ctxt, NULL) != DW_DLV_OK)
		return result;

	if (table_count == 1) {
		Dwarf_Line *linebuf = 0;
		Dwarf_Signed linecount = 0;
		dwarf_srclines_from_linecontext(ctxt, &linebuf, &linecount, NULL);
		Dwarf_Addr prev_lineaddr;
		Dwarf_Line prev_line = 0;
		for (int i = 0; i < linecount; i++) {
			Dwarf_Line line = linebuf[i];
			Dwarf_Addr lineaddr;
			dwarf_lineaddr(line, &lineaddr, NULL);
			if (pc == lineaddr) {
				/* Print the last line entry containing current pc. */
				Dwarf_Line last_pc_line = line;
				for (int j = i + 1; j < linecount; j++) {
					Dwarf_Line j_line = linebuf[j];
					dwarf_lineaddr(j_line, &lineaddr, NULL);
					if (pc == lineaddr) {
						last_pc_line = j_line;
					}
				}
				result = get_source_str_from_line(last_pc_line);
				break;
			} else if (prev_line && pc > prev_lineaddr && pc < lineaddr) {
				result = get_source_str_from_line(prev_line);
				break;
			}
			Dwarf_Bool is_lne;
			dwarf_lineendsequence(line, &is_lne, NULL);
			if (is_lne) {
				prev_line = 0;
			} else {
				prev_lineaddr = lineaddr;
				prev_line = line;
			}
		}
	}

	dwarf_srclines_dealloc_b(ctxt);
	return result;
}

string ElfDebug::get_source_str_from_line(Dwarf_Line line) const {
	string result_src;
	if (!line)
		return result_src;

	// Get source file and line number
	char *src_file;
	Dwarf_Unsigned lineno;
	if (dwarf_linesrc(line, &src_file, NULL) != DW_DLV_OK)
		return result_src;

	result_src = string(src_file);
	bool has_lineno = (dwarf_lineno(line, &lineno, NULL) == DW_DLV_OK);
	string result_lineno = (has_lineno ? to_string(lineno) : "unk");
	dwarf_dealloc(m_dwarf, src_file, DW_DLA_STRING);
	return result_src + ":" + result_lineno;
}

/*
// Currently we are using ELF symbols for this, instead of DWARF info.

static string lookup_symbol_cu(Dwarf_Debug dbg, Dwarf_Addr pc, Dwarf_Die cu_die) {
	Dwarf_Die child_die;

	// Get the CU DIE first child
	if (dwarf_child(cu_die, &child_die, nullptr) != DW_DLV_OK)
		return nknown;

	// Iterate every child
	do {
		// Check it's a function
		Dwarf_Half tag;
		if (dwarf_tag(child_die, &tag, nullptr) != DW_DLV_OK)
			continue;
		if (tag != DW_TAG_subprogram)
			continue;

		// Attempt to get its limits
		Dwarf_Addr low_pc, high_pc;
		if (!get_die_limits(child_die, &low_pc, &high_pc))
			continue;

		if (!(pc >= low_pc && pc < high_pc))
			continue;

		// We got our symbol. Return its name.
		char* die_name = nullptr;
		if (dwarf_diename(child_die, &die_name, nullptr) != DW_DLV_OK)
			return "unknown symbol name";
		return string(die_name);

	} while (dwarf_siblingof_b(dbg, child_die, is_info, &child_die, nullptr) == DW_DLV_OK);

	return unknown;
}

*/
