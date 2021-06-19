#include "process.h"

int Process::do_sys_clone(
	unsigned long flags,
	UserPtr<void*> stack_ptr,
	UserPtr<int*> parent_tid_ptr,
	UserPtr<int*> child_tid_ptr,
	unsigned long tls
) {
	TODO
}

int Process::do_sys_clone3(UserPtr<struct clone_args*> args, size_t size) {
	TODO
}