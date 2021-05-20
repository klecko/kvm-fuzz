#include "process.h"
#include "linux/signal.h"

int Process::do_sys_tgkill(int tgid, int tid, int sig) {
	if (sig == SIGABRT && tgid == m_pid && tid == m_pid) {
		FaultInfo fault = {
			.type = FaultInfo::AssertionFailed,
			.rip = m_user_regs->rip
		};
		hc_end_run(RunEndReason::Crash, &fault);
	}
	TODO
	return 0;
}