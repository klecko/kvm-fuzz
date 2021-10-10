#include "process.h"
#include "scheduler.h"
#include "linux/sched.h"

Process::Process(const Process& other, unsigned long flags)
	: m_pid(s_next_pid++)
	, m_tgid((flags & CLONE_THREAD) ? other.m_tgid : m_pid)
	, m_space((flags & CLONE_VM) ? other.m_space : other.m_space.clone().value())
	, m_files((flags & CLONE_FILES) ? other.m_files.ref() : default_files())
	, m_elf_path(other.m_elf_path)
	, m_brk(other.m_brk)
	, m_min_brk(other.m_min_brk)
	, m_user_regs(other.m_user_regs) // bad when CLONE_VM is specified
{
}

int Process::do_sys_clone(
	unsigned long flags,
	UserPtr<void*> stack_ptr,
	UserPtr<int*> parent_tid_ptr,
	UserPtr<int*> child_tid_ptr,
	unsigned long tls
) {
	// fork: CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD
	// thread: CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
	//         CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
	//         CLONE_CHILD_CLEARTID
	// if (flags & C)
	// Process new_process(*this, flags);
	// // TODO: m_user_regs must be copied into the new stack and the correct location
	// o mejor: cambiar m_user_regs, ahora será m_regs y no será un puntero.

	printf("i'm %d\n", m_pid);

	Process* copy = new Process(*this, flags);
	Scheduler::add(*copy);
	Scheduler::schedule();


	printf("i'm %d\n", m_pid);
	// thread: 0x3d0f00 0x7ffff87fddf0 0x7ffff87fe9d0 0x7ffff87fe9d0 0x7ffff87fe700
	// fork:   0x1200011 0x0 0x0 0x6b3bd0 0x0
	printf("%p %p %p %p %p\n", flags, stack_ptr, parent_tid_ptr, child_tid_ptr, tls);
	return copy->m_pid;
}

int Process::child_return_from_clone() {
	return 0;
}

int Process::do_sys_clone3(UserPtr<struct clone_args*> args, size_t size) {
	TODO
}