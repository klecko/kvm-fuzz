#ifndef _SCHEDULER_H
#define _SCHEDULER_H

#include "process.h"

class Scheduler {
public:
	static Process& current();
};

#endif