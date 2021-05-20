#ifndef _X86_PERF_H
#define _X86_PERF_H

#include "common.h"

namespace Perf {

void init();
size_t instructions_executed();
void tick();

}

#endif