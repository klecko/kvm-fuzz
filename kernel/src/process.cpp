#include "process.h"
#include "syscall_str.h"
#include "fs/file_manager.h"
#include "x86/asm.h"

Process::Process(const VmInfo& info)
	: m_pid(1234)
	, m_space(rdcr3())
	, m_elf_path(info.elf_path)
	, m_brk(info.brk)
	, m_min_brk(info.brk)
{
	m_open_files[STDIN_FILENO] = FileManager::open(FileManager::Stdin);
	m_open_files[STDOUT_FILENO] = FileManager::open(FileManager::Stdout);
	m_open_files[STDERR_FILENO] = FileManager::open(FileManager::Stderr);
	dbgprintf("Elf path: %s\n", m_elf_path.c_str());
	dbgprintf("Brk: %p\n", m_brk);
}

int Process::available_fd() {
	int fd = 0;
	while (m_open_files.count(fd)) {
		fd++;
		ASSERT(fd > 0, "we ran out of fds?");
	}
	return fd;
}


const char* syscall_str[500];

size_t syscall_counts[500];
void print_syscalls() {
	int sum = 0;
	for (int i = 0; i < 500; i++) {
		if (syscall_counts[i]) {
			printf("%s: %d\n", syscall_str[i], syscall_counts[i]);
			sum += syscall_counts[i];
		}
	}
	printf("total: %d\n", sum);
}

uint64_t Process::handle_syscall(int nr, uint64_t arg0, uint64_t arg1,
                                 uint64_t arg2, uint64_t arg3,
								 uint64_t arg4, uint64_t arg5, Regs* regs)
{
	dbgprintf("--> syscall at %p: %s\n", regs->rip, syscall_str[nr]);
	m_user_regs = regs;
	syscall_counts[nr]++;
	uint64_t ret = 0;
	switch (nr) {
		case SYS_openat:
			//hc_print_stacktrace(regs->rsp, regs->rip, regs->rbp);
			ret = do_sys_openat(arg0, UserPtr<const char*>(arg1), arg2, arg3);
			break;
		case SYS_open:
			ret = do_sys_open(UserPtr<const char*>(arg0), arg1, arg2);
			break;
		case SYS_read:
			ret = do_sys_read(arg0, UserPtr<void*>(arg1), arg2);
			break;
		case SYS_pread64:
			ret = do_sys_pread64(arg0, UserPtr<void*>(arg1), arg2, arg3);
			break;
		case SYS_write:
			ret = do_sys_write(arg0, UserPtr<const void*>(arg1), arg2);
			break;
		case SYS_writev:
			ret = do_sys_writev(arg0, UserPtr<const iovec*>(arg1), arg2);
			break;
		case SYS_access:
			ret = do_sys_access(UserPtr<const char*>(arg0), arg1);
			break;
		case SYS_lseek:
			ret = do_sys_lseek(arg0, arg1, arg2);
			break;
		case SYS_close:
			ret = do_sys_close(arg0);
			break;
		case SYS_dup:
			ret = do_sys_dup(arg0);
			break;
		case SYS_brk:
			ret = do_sys_brk(arg0);
			break;
		case SYS_exit:
		case SYS_exit_group:
			//dbgprintf("end run --------------------------------\n\n");
			//print_syscalls();
			hc_end_run();
			break;
		case SYS_getuid:
		case SYS_getgid:
		case SYS_geteuid:
		case SYS_getegid:
			ret = 0;
			break;
		case SYS_getpid:
		case SYS_gettid:
			ret = m_pid;
			break;
		case SYS_arch_prctl:
			ret = do_sys_arch_prctl(arg0, arg1);
			break;
		case SYS_uname:
			ret = do_sys_uname(UserPtr<struct new_utsname*>(arg0));
			break;
		case SYS_readlink:
			ret = do_sys_readlink(UserPtr<const char*>(arg0),
			                      UserPtr<char*>(arg1), arg2);
			break;
		case SYS_mmap:
			ret = do_sys_mmap(UserPtr<void*>(arg0), arg1, arg2, arg3, arg4, arg5);
			break;
		case SYS_munmap:
			ret = do_sys_munmap(UserPtr<void*>(arg0), arg1);
			break;
		case SYS_mprotect:
			ret = do_sys_mprotect(UserPtr<void*>(arg0), arg1, arg2);
			break;
		case SYS_fstat:
			ret = do_sys_fstat(arg0, UserPtr<struct stat*>(arg1));
			break;
		case SYS_stat:
			ret = do_sys_stat(UserPtr<const char*>(arg0),
			                  UserPtr<struct stat*>(arg1));
			break;
		case SYS_ioctl:
			ret = do_sys_ioctl(arg0, arg1, arg2);
			break;
		case SYS_fcntl:
			ret = do_sys_fcntl(arg0, arg1, arg2);
			break;
		case SYS_prlimit64:
			ret = do_sys_prlimit(arg0, arg1, UserPtr<const struct rlimit*>(arg2),
			                     UserPtr<struct rlimit*>(arg3));
			break;
		case SYS_sysinfo:
			ret = do_sys_sysinfo(UserPtr<struct sysinfo*>(arg0));
			break;
		case SYS_tgkill:
			ret = do_sys_tgkill(arg0, arg1, arg2);
			break;
		case SYS_clock_gettime:
			ret = do_sys_clock_gettime(arg0, UserPtr<struct timespec*>(arg1));
			break;
		case SYS_set_tid_address:
			ret = 0;
			printf_once("TODO set_tid_address\n");
			break;
		case SYS_set_robust_list:
			ret = 0;
			printf_once("TODO set_robust_list\n");
			break;
		case SYS_rt_sigaction:
			ret = 0;
			printf_once("TODO rt_sigaction\n");
			break;
		case SYS_rt_sigprocmask:
			ret = 0;
			printf_once("TODO rt_sigprocmask\n");
			break;
		case SYS_futex:
			ret = 0;
			printf_once("TODO futex\n");
			break;
		case SYS_sigaltstack:
			ret = 0;
			printf_once("TODO sigaltstack\n");
			break;

		default:
			hc_print_stacktrace(regs->rsp, regs->rip, regs->rbp);
			die("Unimplemented syscall: %s (%lld)\n", syscall_str[nr], nr);
	}

	dbgprintf("<-- syscall: %s returned 0x%lx\n", syscall_str[nr], ret);
	return ret;
}