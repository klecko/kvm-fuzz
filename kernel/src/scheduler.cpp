#include "scheduler.h"

namespace Scheduler {

static bool g_running;
static Process* g_active_process;

void init(Process& first_process) {
	g_active_process = &first_process;
	g_running = false;
}

bool is_running() {
	return g_running;
}

Process& current() {
	ASSERT(g_active_process, "scheduler not initialized");
	return *g_active_process;
}

}