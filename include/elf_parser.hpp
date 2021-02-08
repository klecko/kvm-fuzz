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

#ifndef H_ELF_PARSER
#define H_ELF_PARSER

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>    /* O_RDONLY */
#include <sys/stat.h> /* For the size of the file. , fstat */
#include <sys/mman.h> /* mmap, MAP_PRIVATE */
#include <vector>
#include <elf.h>      // Elf64_Shdr
#include <fcntl.h>
#include "common.h"

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

#endif

struct phinfo_t {
    vaddr_t  e_phoff;      /* Program header table file offset */
    uint16_t e_phentsize;  /* Program header table entry size */
    uint16_t e_phnum;      /* Program header table entry count */
};

struct section_t {
    uint16_t    index; 
    vaddr_t     offset;
    vaddr_t     addr;
    std::string name;
    std::string type; 
    vsize_t     size;
    vsize_t     ent_size; 
    uint32_t    addr_align;
};

struct segment_t {
    std::string type;
    std::string flags;
    vaddr_t     offset;
    vaddr_t     virtaddr;
    vaddr_t     physaddr;
    vsize_t     filesize;
    vsize_t     memsize;
    uint32_t    align;
    void*       data;
};

struct symbol_t {
    std::string index;
    vaddr_t     value;
    uint32_t    num;
    vsize_t     size;
    std::string type;
    std::string bind;
    std::string visibility;
    std::string name;
    std::string section;      
};

struct relocation_t {
    vaddr_t     offset;
    uint32_t    info;
    vaddr_t     symbol_value;
    std::string type;
    std::string symbol_name;
    std::string section_name;
    vaddr_t     plt_address;
};


class Elf_parser {
    public:
        Elf_parser (const std::string &elf_path);
        vaddr_t get_entry() const;
        vaddr_t get_load_addr() const {return m_load_addr;};
        std::string get_path() const;
        std::string get_abs_path() const;
        phinfo_t get_phinfo() const;
        std::vector<section_t> get_sections() const;
        std::vector<segment_t> get_segments() const;
        std::vector<symbol_t> get_symbols() const;
        std::vector<relocation_t> get_relocations() const;
        uint8_t *get_memory_map() const;

    private:
        void load_memory_map();

        std::string get_section_type(uint32_t tt) const;

        std::string get_segment_type(Elf32_Word seg_type) const;
        std::string get_segment_flags(Elf32_Word seg_flags) const;

        std::string get_symbol_type(uint8_t sym_type) const;
        std::string get_symbol_bind(uint8_t sym_bind) const;
        std::string get_symbol_visibility(uint8_t sym_vis) const;
        std::string get_symbol_index(Elf32_Half sym_idx) const;

        std::string get_relocation_type(Elf32_Word rela_type) const;
        vaddr_t     get_rel_symbol_value(Elf32_Word sym_idx,
                                         const std::vector<symbol_t>& syms) const;
        std::string get_rel_symbol_name(Elf32_Word sym_idx,
                                        const std::vector<symbol_t>& syms) const;

        std::string m_elf_path;
        std::string m_elf_abs_path;
        uint8_t*    m_mmap_program;
        vaddr_t     m_load_addr;
};

#endif