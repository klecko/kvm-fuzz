#include "scheduler.h"

namespace Scheduler {

static size_t g_active_i;
static vector<Process*> g_processes;

void init(Process& first_process) {
	g_processes.push_back(&first_process);
	g_active_i = 0;
}

void add(Process& process) {
	g_processes.push_back(&process);
}

Process& current() {
	ASSERT(!g_processes.empty(), "scheduler not initialized");
	return *g_processes[g_active_i];
}

static void next() {
	g_active_i = (g_active_i + 1) % g_processes.size();
}

__attribute__((noinline))
void schedule() {
	printf("scheduling %lu\n", g_processes.size());
	ASSERT(!g_processes.empty(), "scheduler not initialized");
	if (g_processes.size() == 1)
		return;

	Process& cur = current();
	next();
	Process& next = current();

	// Switch address space if needed
	if (cur.space() != next.space())
		next.space().load();
}

}