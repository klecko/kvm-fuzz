#ifndef _X86_GDT_ENTRY_H
#define _X86_GDT_ENTRY_H

#include "common.h"

namespace GDT {

// https://wiki.osdev.org/Global_Descriptor_Table
// https://wiki.osdev.org/GDT_Tutorial
struct GlobalDescriptor {
public:
	static const int GDT_TSS_TYPE                = 9;
	static const int GDT_SHIFT_ACCESS_ACCESSED   = 0;
	static const int GDT_SHIFT_ACCESS_RW         = 1;
	static const int GDT_SHIFT_ACCESS_DC         = 2;
	static const int GDT_SHIFT_ACCESS_EX         = 3;
	static const int GDT_SHIFT_ACCESS_S          = 4;
	static const int GDT_SHIFT_ACCESS_DPL        = 5;
	static const int GDT_SHIFT_ACCESS_PRESENT    = 7;
	static const int GDT_SHIFT_FLAGS_LONG        = 5;
	static const int GDT_SHIFT_FLAGS_SZ          = 6;
	static const int GDT_SHIFT_FLAGS_GRANULARITY = 7;

	// This needs to be 0 for the NULL descriptor
	uint16_t m_limit_low      = 0;
	uint16_t m_base_low       = 0;
	uint8_t  m_base_mid       = 0;
	uint8_t  m_access         = 0;
	uint8_t  m_limit_hi_flags = 0;
	uint8_t  m_base_hi        = 0;

	void set_common() {
		// Set common stuff. Bit EX will be set by `set_code()` or `set_data()`
		m_access = (0 << GDT_SHIFT_ACCESS_ACCESSED)
		         | (1 << GDT_SHIFT_ACCESS_RW) // readable in code, writable in data
		         | (0 << GDT_SHIFT_ACCESS_DC) // can only be executed in dpl / grows up
		         | (1 << GDT_SHIFT_ACCESS_S)  // set for code and data
		         | (1 << GDT_SHIFT_ACCESS_PRESENT);
		m_limit_hi_flags |= (1 << GDT_SHIFT_FLAGS_LONG)
		                  | (0 << GDT_SHIFT_FLAGS_SZ)           // 0 for long mode
		                  | (1 << GDT_SHIFT_FLAGS_GRANULARITY); // page granularity
		set_base(0);
		set_limit(0xFFFFF);
	}

	void set_limit(uint32_t limit) {
		ASSERT(limit <= 0xFFFFF, "oob limit: %hu", limit);
		m_limit_low = limit & 0xFFFF;
		m_limit_hi_flags |= (limit >> 16) & 0xF;
	}

	void set_base(uint32_t base) {
		m_base_low = base & 0xFFFF;
		m_base_mid = (base >> 16) & 0xFF;
		m_base_hi  = (base >> 24) & 0xFF;
	}

public:
	void set_code() {
		set_common();
		m_access |= (1 << GDT_SHIFT_ACCESS_EX); // executable
	}

	void set_data() {
		set_common();
		m_access |= (0 << GDT_SHIFT_ACCESS_EX); // not executable
	}

	void set_dpl(uint8_t dpl) {
		ASSERT(dpl <= 3, "invalid dpl: %hhu", dpl);
		m_access |= dpl << GDT_SHIFT_ACCESS_DPL;
	}

} __attribute__((packed));

struct TSSDescriptor : GlobalDescriptor {
private:
	uint32_t m_base_hi2 = 0;
	uint32_t m_zero     = 0;

public:
	TSSDescriptor() {
		set_dpl(3);
		set_limit(104);
		m_access |= (1 << GDT_SHIFT_ACCESS_PRESENT);
		m_access |= GDT_TSS_TYPE;
	}

	void set_base(uint64_t base) {
		GlobalDescriptor::set_base((uint32_t)base);
		m_base_hi2 = (base >> 32);
	}

} __attribute__((packed));

struct GDTPtr {
	uint16_t size;
	uint64_t offset;
	void load(uint16_t segment_selector_tss) {
		// Maybe it's SEGMENT_SELECTOR_TSS | 3
		asm volatile("lgdt %0" : : "m"(*this));
		asm volatile("ltr %0" : : "r"((uint16_t)segment_selector_tss));
	}
} __attribute__((packed));

}

#endif