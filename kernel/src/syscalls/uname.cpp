#include "process.h"
#include "linux/utsname.h"

int Process::do_sys_uname(UserPtr<struct new_utsname*> uname_ptr) {
	constexpr static struct new_utsname uname = {
		"Linux",                                              // sysname
		"pep1t0",                                             // nodename
		"5.8.0-43-generic",                                   // release
		"#49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021", // version
		"x86_64"                                              // machine
	};
	return (copy_to_user(uname_ptr, &uname) ? 0 : -EFAULT);
}