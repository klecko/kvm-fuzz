// MIT License

// Copyright (c) 2018 finixbit

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "elf_parser.hpp"
#include <linux/limits.h> // PATH_MAX
#include <cstring>

using namespace std;

Elf_parser::Elf_parser(const string& elf_path): m_elf_path(elf_path) {
    // Save absolute file path. Ugly conversions here
	char abspath[PATH_MAX];
	if (!realpath(elf_path.c_str(), abspath))
		die("error realpath: %s\n", strerror(errno));
	m_elf_abs_path.assign(abspath);

    // Load memory map
    load_memory_map();

    // Get load address
    m_load_addr = UINT32_MAX;
    for (const segment_t& s : get_segments())
        m_load_addr = min(m_load_addr, s.virtaddr);
}

string Elf_parser::get_path() const{
    return m_elf_path;
}

string Elf_parser::get_abs_path() const{
    return m_elf_abs_path;
}

vaddr_t Elf_parser::get_entry() const {
    return ((Elf_Ehdr*)m_mmap_program)->e_entry;
}

phinfo_t Elf_parser::get_phinfo() const{
    Elf_Ehdr* ehdr = (Elf_Ehdr*)m_mmap_program;
    phinfo_t result = {
        ehdr->e_phoff,
        ehdr->e_phentsize,
        ehdr->e_phnum
    };
    return result;
}

std::vector<section_t> Elf_parser::get_sections() const {
    Elf_Ehdr* ehdr  = (Elf_Ehdr*)(m_mmap_program);
    Elf_Shdr* shdr  = (Elf_Shdr*)(m_mmap_program + ehdr->e_shoff);
    Elf_Half  shnum = ehdr->e_shnum;

    Elf_Shdr* sh_strtab   = &shdr[ehdr->e_shstrndx];
    const char* sh_strtab_p = (char*)m_mmap_program + sh_strtab->sh_offset;

    std::vector<section_t> sections;
    for (uint16_t i = 0; i < shnum; ++i) {
        section_t section;
        section.index      = i;
        section.name       = std::string(sh_strtab_p + shdr[i].sh_name);
        section.type       = get_section_type(shdr[i].sh_type);
        section.addr       = shdr[i].sh_addr;
        section.offset     = shdr[i].sh_offset;
        section.size       = shdr[i].sh_size;
        section.ent_size   = shdr[i].sh_entsize;
        section.addr_align = shdr[i].sh_addralign; 
        sections.push_back(section);
    }
    return sections;
}

std::vector<segment_t> Elf_parser::get_segments() const {
    Elf_Ehdr*ehdr = (Elf_Ehdr*)(m_mmap_program);
    Elf_Phdr*phdr = (Elf_Phdr*)(m_mmap_program + ehdr->e_phoff);
    uint16_t phnum  = ehdr->e_phnum;

    std::vector<segment_t> segments;
    for (uint16_t i = 0; i < phnum; ++i) {
        segment_t segment;
        segment.type     = get_segment_type(phdr[i].p_type);
        segment.offset   = phdr[i].p_offset;
        segment.virtaddr = phdr[i].p_vaddr;
        segment.physaddr = phdr[i].p_paddr;
        segment.filesize = phdr[i].p_filesz;
        segment.memsize  = phdr[i].p_memsz;
        segment.flags    = get_segment_flags(phdr[i].p_flags);
        segment.align    = phdr[i].p_align;
        segment.data     = m_mmap_program+segment.offset;
        segments.push_back(segment);
    }
    return segments;
}

std::vector<symbol_t> Elf_parser::get_symbols() const {
    std::vector<section_t> secs = get_sections();

    // get strtab
    char *sh_strtab_p = nullptr;
    for(const section_t& sec : secs) {
        if((sec.type == "SHT_STRTAB") && (sec.name == ".strtab")){
            sh_strtab_p = (char*)m_mmap_program + sec.offset;
            break;
        }
    }

    // get dynstr
    char *sh_dynstr_p = nullptr;
    for(const section_t& sec: secs) {
        if((sec.type == "SHT_STRTAB") && (sec.name == ".dynstr")){
            sh_dynstr_p = (char*)m_mmap_program + sec.offset;
            break;
        }
    }

    std::vector<symbol_t> symbols;
    for(const section_t& sec : secs) {
        if((sec.type != "SHT_SYMTAB") && (sec.type != "SHT_DYNSYM"))
            continue;

        vsize_t    total_syms = sec.size / sizeof(Elf_Sym);
        Elf_Sym* syms_data  = (Elf_Sym*)(m_mmap_program + sec.offset);

        for (vsize_t i = 0; i < total_syms; ++i) {
            symbol_t symbol;
            symbol.num        = i;
            symbol.value      = syms_data[i].st_value;
            symbol.size       = syms_data[i].st_size;
            symbol.type       = get_symbol_type(syms_data[i].st_info);
            symbol.bind       = get_symbol_bind(syms_data[i].st_info);
            symbol.visibility = get_symbol_visibility(syms_data[i].st_other);
            symbol.index      = get_symbol_index(syms_data[i].st_shndx);
            symbol.section    = sec.name;

            if(sec.type == "SHT_SYMTAB")
                symbol.name  = std::string(sh_strtab_p + syms_data[i].st_name);

            if(sec.type == "SHT_DYNSYM")
                symbol.name  = std::string(sh_dynstr_p + syms_data[i].st_name);
            
            symbols.push_back(symbol);
        }
    }
    return symbols;
}

std::vector<relocation_t> Elf_parser::get_relocations() const {
    auto secs = get_sections();
    auto syms = get_symbols();
    
    vsize_t plt_entry_size  = 0;
    vaddr_t plt_vma_address = 0;

    for (const section_t& sec : secs) {
        if(sec.name == ".plt") {
          plt_entry_size  = sec.ent_size;
          plt_vma_address = sec.addr;
          break;
        }
    }

    std::vector<relocation_t> relocations;
    for (const section_t& sec : secs) {
        if(sec.type != "SHT_RELA") 
            continue;

        vsize_t     total_relas = sec.size / sizeof(Elf_Rela);
        Elf_Rela* relas_data  = (Elf_Rela*)(m_mmap_program + sec.offset);

        for (vsize_t i = 0; i < total_relas; ++i) {
            relocation_t rel;
            rel.offset = relas_data[i].r_offset;
            rel.info   = relas_data[i].r_info;
            rel.type   = get_relocation_type(relas_data[i].r_info);
            rel.symbol_value = get_rel_symbol_value(relas_data[i].r_info, syms);
            rel.symbol_name  = get_rel_symbol_name (relas_data[i].r_info, syms);
            rel.plt_address  = plt_vma_address + (i + 1) * plt_entry_size;
            rel.section_name = sec.name;
            relocations.push_back(rel);
        }
    }
    return relocations;
}

uint8_t *Elf_parser::get_memory_map() const {
    return m_mmap_program;
}

void Elf_parser::load_memory_map() {
    struct stat st;
    int fd = open(m_elf_path.c_str(), O_RDONLY);
    if (fd < 0){
        perror("elf_parser: open");
        exit(EXIT_FAILURE);
    }
    if (fstat(fd, &st) < 0){
        perror("elf_parser: stat");
        exit(EXIT_FAILURE);
    }

    m_mmap_program = 
        (uint8_t*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m_mmap_program == MAP_FAILED) {
        perror("elf_parser: mmap");
        exit(-1);
    }

    Elf_Ehdr* header = (Elf_Ehdr*)m_mmap_program;
    if (header->e_ident[EI_CLASS] != ELFCLASS)
        die("elf_parser: ELFCLASS doesn't match\n");
    if (header->e_machine != EM_X86_64)
        die("elf_parser: ARCH doesn't match\n");
}

std::string Elf_parser::get_section_type(Elf_Word tt) const {
    switch(tt) {
        case 0:  return "SHT_NULL";     // Section header table entry unused
        case 1:  return "SHT_PROGBITS"; // Program data
        case 2:  return "SHT_SYMTAB";   // Symbol table
        case 3:  return "SHT_STRTAB";   // String table
        case 4:  return "SHT_RELA";     // Relocation entries with addends
        case 5:  return "SHT_HASH";     // Symbol hash table
        case 6:  return "SHT_DYNAMIC";  // Dynamic linking information
        case 7:  return "SHT_NOTE";     // Notes
        case 8:  return "SHT_NOBITS";   // Program space with no data (bss)
        case 9:  return "SHT_REL";      // Relocation entries, no addends
        case 11: return "SHT_DYNSYM";   // Dynamic linker symbol table
        default: return "UNKNOWN";
    }
}

std::string Elf_parser::get_segment_type(Elf_Word seg_type) const {
    switch(seg_type) {
        case PT_NULL:      return "NULL";      // Program header entry unused 
        case PT_LOAD:      return "LOAD";      // Loadable program segment
        case PT_DYNAMIC:   return "DYNAMIC";   // Dynamic linking information
        case PT_INTERP:    return "INTERP";    // Program interpreter
        case PT_NOTE:      return "NOTE";      // Auxiliary information
        case PT_SHLIB:     return "SHLIB";     // Reserved
        case PT_PHDR:      return "PHDR";      // Entry for header table itself
        case PT_TLS:       return "TLS";       // Thread-local storage segment
        case PT_NUM:       return "NUM";       // Number of defined types
        case PT_LOOS:      return "LOOS";      // Start of OS-specific
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME"; // GCC .eh_frame_hdr segmnt
        case PT_GNU_STACK: return "GNU_STACK"; // Indicates stack executability
        case PT_GNU_RELRO: return "GNU_RELRO"; // Read-only after relocation
        case PT_SUNWBSS:   return "SUNWBSS";   // Sun Specific segment
        case PT_SUNWSTACK: return "SUNWSTACK"; // Stack segment
        case PT_HIOS:      return "HIOS";      // End of OS-specific
        case PT_LOPROC:    return "LOPROC";    // Start of processor-specific
        case PT_HIPROC:    return "HIPROC";    // End of processor-specific
        default: return "UNKNOWN";
    }
}

std::string Elf_parser::get_segment_flags(Elf_Word seg_flags) const {
    std::string flags;
    if(seg_flags & PF_R)
        flags.append("R");
    if(seg_flags & PF_W)
        flags.append("W");
    if(seg_flags & PF_X)
        flags.append("E");
    return flags;
}

std::string Elf_parser::get_symbol_type(uint8_t sym_type) const {
    switch(ELF_ST_TYPE(sym_type)) {
        case 0:  return "NOTYPE";
        case 1:  return "OBJECT";
        case 2:  return "FUNC";
        case 3:  return "SECTION";
        case 4:  return "FILE";
        case 6:  return "TLS";
        case 7:  return "NUM";
        case 10: return "LOOS";
        case 12: return "HIOS";
        default: return "UNKNOWN";
    }
}

std::string Elf_parser::get_symbol_bind(uint8_t sym_bind) const {
    switch(ELF_ST_BIND(sym_bind)) {
        case 0:  return "LOCAL";
        case 1:  return "GLOBAL";
        case 2:  return "WEAK";
        case 3:  return "NUM";
        case 10: return "UNIQUE";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        default: return "UNKNOWN";
    }
}

std::string Elf_parser::get_symbol_visibility(uint8_t sym_vis) const {
    switch(ELF_ST_VISIBILITY(sym_vis)) {
        case 0:  return "DEFAULT";
        case 1:  return "INTERNAL";
        case 2:  return "HIDDEN";
        case 3:  return "PROTECTED";
        default: return "UNKNOWN";
    }
}

std::string Elf_parser::get_symbol_index(Elf_Half sym_idx) const {
    switch(sym_idx) {
        case SHN_ABS:    return "ABS";
        case SHN_COMMON: return "COM";
        case SHN_UNDEF:  return "UND";
        case SHN_XINDEX: return "COM";
        default:         return std::to_string(sym_idx);
    }
}

std::string Elf_parser::get_relocation_type(Elf_Word rela_type) const {
    switch(ELF_R_TYPE(rela_type)) {
        case 1:  return "R_386_32";
        case 2:  return "R_386_PC32";
        case 5:  return "R_386_COPY";
        case 6:  return "R_386_GLOB_DAT";
        case 7:  return "R_386_JMP_SLOT";
        default: return "OTHERS";
    }
}

vaddr_t Elf_parser::get_rel_symbol_value(Elf_Word sym_idx, 
                                         const std::vector<symbol_t>& syms) const
{    
    vaddr_t sym_val = 0;
    for(const symbol_t& sym : syms) {
        if(sym.num == ELF_R_SYM(sym_idx)) {
            sym_val = sym.value;
            break;
        }
    }
    return sym_val;
}

std::string Elf_parser::get_rel_symbol_name(Elf_Word sym_idx,
                                            const std::vector<symbol_t>& syms) const
{
    std::string sym_name;
    for(const symbol_t& sym : syms) {
        if(sym.num == ELF_R_SYM(sym_idx)) {
            sym_name = sym.name;
            break;
        }
    }
    return sym_name;
}
