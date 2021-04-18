#ifndef _X86_PIT_H
#define _X86_PIT_H

#include "common.h"

namespace PIT {

void configure_sleep(uint64_t microsecs);
void perform_sleep();

}

#endif