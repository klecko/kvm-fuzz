#include "pit.h"
#include "x86/asm.h"

namespace PIT {

void configure_sleep(uint64_t microsecs) {
	// PIT runs at 1.193182 MHz, which means it's decremented 1193182 times
	// per second.
	constexpr uint64_t PIT_RATE = 1193182;
	constexpr uint64_t MAX_MICROSECS = UINT16_MAX * 1000000UL / PIT_RATE;

	ASSERT(microsecs < MAX_MICROSECS, "too high microsecs %lu, max is %lu",
	       microsecs, MAX_MICROSECS);
	uint16_t val = microsecs * PIT_RATE / (1000000UL);

	// Set input
	outb(0x61, inb(0x61) | 1);

	// Configure PIT
	constexpr uint8_t channel = 0b10 << 6;         // channel 2
	constexpr uint8_t access_mode = 0b11 << 4;     // lobyte/hibyte
	constexpr uint8_t operating_mode = 0b001 << 1; // one-shot
	constexpr uint8_t binary_mode = 0b0;
	outb(0x43, channel | access_mode | operating_mode | binary_mode);

	// Write value to channel 2
	outb(0x42, val & 0xFF); // lobyte
	outb(0x42, val >> 8);   // hibyte
}

void perform_sleep() {
	// Clear input, set it and wait until output is 0
	outb(0x61, inb(0x61) & ~1);
	outb(0x61, inb(0x61) | 1);
	while (inb(0x61) & 0x20);
}

}