#ifndef _IDT_H
#define _IDT_H

#include "common.h"
#include "gdt.h"

#define N_IDT_ENTRIES 256

// https://wiki.osdev.org/Interrupt_Descriptor_Table
struct InterruptDescriptor {
private:
	static const int IDT_SHIFT_PRESENT = 7;
	static const int IDT_SHIFT_DPL     = 5;
	static const int IDT_SHIFT_S       = 4;
	static const int IDT_SHIFT_TYPE    = 0;

	uint16_t m_offset_low  = 0;
	uint16_t m_selector    = SEGMENT_SELECTOR_KCODE;
	uint8_t  m_ist         = 0;
	uint8_t  m_attributes  = 0;
	uint16_t m_offset_mid  = 0;
	uint32_t m_offset_high = 0;
	uint32_t m_zero        = 0;

public:
	enum Type : uint8_t {
		Task      = 0b0101,
		Interrupt = 0b1110,
		Trap      = 0b1111,
	};

	void set_offset(uint64_t handler) {
		m_offset_low  = (uint16_t)(handler & 0xFFFF);
		m_offset_mid  = (uint16_t)((handler >> 16) & 0xFFFF);
		m_offset_high = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
	}

	void set_selector(uint16_t selector) {
		m_selector = selector;
	}

	void set_ist(uint8_t ist) {
		ASSERT(ist <= 7, "invalid ist: %hhu", ist);
		m_ist = ist;
	}

	void set_present() {
		m_attributes |= (1 << IDT_SHIFT_PRESENT);
	}

	void set_dpl(uint8_t dpl) {
		ASSERT(dpl <= 3, "invalid dpl: %hhu", dpl);
		m_attributes |= (dpl << IDT_SHIFT_DPL);
	}

	void set_type(Type t) {
		m_attributes |= (t << IDT_SHIFT_TYPE);
	}

} __attribute__((packed));

struct IDTR {
	uint16_t size;
	uint64_t offset;
	void load() {
		asm volatile("lidt %0" : : "m"(*this));
	}
} __attribute__((packed));

#endif