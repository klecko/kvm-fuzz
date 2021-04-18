#include "process.h"
#include "x86/asm.h"
#include "asm/prctl.h"

int Process::do_sys_arch_prctl(int code, uint64_t addr) {
	uint64_t ret = 0;
	switch (code) {
		case ARCH_SET_FS:
			wrmsr(MSR_FS_BASE, addr);
			break;
		case ARCH_SET_GS:
		case ARCH_GET_FS:
		case ARCH_GET_GS:
			TODO
		default:
			ret = -EINVAL;
	};

	return ret;
}