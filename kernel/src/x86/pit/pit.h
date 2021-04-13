#ifndef _PIT_H
#define _PIT_H

#include "common.h"

namespace PIT {

void configure_sleep(uint64_t microsecs);
void perform_sleep();

}

#endif