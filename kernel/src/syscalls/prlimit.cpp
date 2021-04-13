#include "process.h"

int Process::do_sys_prlimit(pid_t pid, int resource,
                            UserPtr<const struct rlimit*> new_limit_ptr,
                            UserPtr<struct rlimit*> old_limit_ptr)
{
	// PID 0 refers to calling process' PID
	ASSERT(pid == m_pid || pid == 0, "TODO pid %d", pid);
	if (!old_limit_ptr.is_null()) {
		struct rlimit limit;
		switch (resource) {
			case RLIMIT_NOFILE:
				limit.rlim_cur = 1024;
				limit.rlim_max = 1024*1024;
				break;
			case RLIMIT_STACK:
				limit.rlim_cur = 8*1024*1024;
				limit.rlim_max = RLIM64_INFINITY;
				break;
			default:
				ASSERT(false, "TODO get limit %d", resource);
		}
		if (!copy_to_user(old_limit_ptr, &limit))
			return -EFAULT;
	}

	if (!new_limit_ptr.is_null()) {
		switch (resource) {
			case RLIMIT_CORE:
				break;
			default:
				ASSERT(false, "TODO set limit %d", resource);
		}
	}
	return 0;
}