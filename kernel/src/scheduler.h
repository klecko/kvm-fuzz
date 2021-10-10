#ifndef _SCHEDULER_H
#define _SCHEDULER_H

#include "process.h"

namespace Scheduler {

void init(Process& first_process);
void add(Process& process);
Process& current();
void schedule();

};

#endif