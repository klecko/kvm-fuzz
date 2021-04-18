#include "process.h"

int Process::do_sys_sysinfo(UserPtr<struct sysinfo*> info_ptr) {
	static constexpr struct sysinfo sys = {
		.uptime    = 1234,
		.loads     = {102176, 105792, 94720},
		.totalram  = 32UL*1024*1024*1024,
		.freeram   = 26UL*1024*1024*1024,
		.sharedram = 1UL *1024*1024*1024,
		.bufferram = 1UL *1024*1024*1024,
		.totalswap = 2UL *1024*1024*1024,
		.freeswap  = 2UL *1024*1024*1024,
		.procs     = 1234,
		.totalhigh = 0,
		.freehigh  = 0,
		.mem_unit  = 1
	};
	return (copy_to_user(info_ptr, &sys) ? 0 : -EFAULT);
}