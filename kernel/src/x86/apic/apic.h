#ifndef _X86_APIC_H
#define _X86_APIC_H

#include "common.h"

namespace APIC {
	void init();
	void reset_timer();
	size_t timer_microsecs();
}

#endif