#include "process.h"

int Process::do_sys_clock_gettime(clockid_t clock_id,
                                  UserPtr<struct timespec*> tp_ptr)
{
	printf_once("TODO: clock_gettime\n");
	struct timespec tp = {
		.tv_sec = 0,
		.tv_nsec = 0,
	};
	if (!copy_to_user(tp_ptr, &tp))
		return -EFAULT;
	return 0;
}