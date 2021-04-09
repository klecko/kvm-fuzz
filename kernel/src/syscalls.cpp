#define _GNU_SOURCE
#include "syscalls.h"
#include "common.h"
#include "user.h"
#include "syscall_str.h"
#include "asm.h"
#include "mem.h"
#include "string"
#include "user_ptr.h"

// Linux
#include "asm/prctl.h"
#include "linux/fcntl.h"
#include "linux/utsname.h"
#include "linux/mman.h"
#include "linux/resource.h"
#include "linux/sysinfo.h"
#include "linux/types.h"
#include "linux/signal.h"
#include "linux/fs.h"
#include "linux/others.h"

// Global user state
string m_elf_path;
uintptr_t m_brk;
uintptr_t m_min_brk;
unordered_map<int, File> m_open_files;
unordered_map<string, struct iovec> m_file_contents;
struct termios2 m_term;
Regs* m_user_regs;

static const int MY_PID = 1234;

const char* syscall_str[500];

static int do_sys_arch_prctl(int code, unsigned long addr) {
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

static int do_sys_openat(int dirfd, UserPtr<const char*> pathname_ptr,
                         int flags, mode_t mode)
{
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;

	ASSERT(dirfd == AT_FDCWD, "%s dirfd %d", pathname.c_str(), dirfd);
	dbgprintf("opening %s\n", pathname_ptr);

	// Find unused fd
	int fd = 3;
	while (m_open_files.count(fd))
		fd++;

	// Create file
	if (pathname == "-") {
		m_open_files[fd] = FileStdout();
	} else {
		ASSERT(m_file_contents.count(pathname), "unknown file '%s'",
		       pathname.c_str());
		ASSERT(!((flags & O_WRONLY) || (flags & O_RDWR)),
		       "%s with write permisions", pathname.c_str());
		struct iovec buf = m_file_contents[pathname];
		m_open_files[fd] = File(flags, (const char*)buf.iov_base, buf.iov_len);
	}
	return fd;
}

static int do_sys_open(UserPtr<const char*> pathname_ptr, int flags,
                       mode_t mode)
{
	return do_sys_openat(AT_FDCWD, pathname_ptr, flags, mode);
}

static ssize_t do_sys_writev(int fd, UserPtr<const struct iovec*> iov_ptr,
                             int iovcnt)
{
	ASSERT(m_open_files.count(fd), "writev: not open fd: %d", fd);
	ASSERT(iovcnt >= 0, "negative iovcnt: %d", iovcnt);
	ssize_t ret  = 0;
	File&   file = m_open_files[fd];

	// Write each iovec to file
	hc_print("WRITEV\n");
	struct iovec iov;
	for (int i = 0; i < iovcnt; i++) {
		// Copy iovec
		if (!copy_from_user(&iov, iov_ptr + i))
			return -EFAULT;

		// Perform write
		ssize_t n = file.write(UserPtr<const void*>(iov.iov_base), iov.iov_len);
		// ssize_t n = print_user(UserPtr<const void*>(iov.iov_base), iov.iov_len);
		if (n < 0)
			return n;
		ret += n;
	}

	//hc_print_stacktrace(m_user_regs->rsp, m_user_regs->rip, m_user_regs->rbp);
	// FaultInfo fault = {
	// 	.type = FaultInfo::Type::AssertionFailed,
	// 	.rip = m_user_regs->rip,
	// };
	// hc_fault(&fault);
	return ret;
}

static ssize_t do_sys_read(int fd, UserPtr<void*> buf, size_t count) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd); // EBADF
	return m_open_files[fd].read(buf, count);
}

static ssize_t do_sys_pread64(int fd, UserPtr<void*> buf, size_t count,
                              off_t offset)
{
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	ASSERT(offset >= 0, "negative offset on fd %d: %ld", fd, offset);

	// Change offset, read and restore offset
	File& file = m_open_files[fd];
	size_t original_offset = file.offset();
	file.set_offset(offset);
	ssize_t ret = file.read(buf, count);
	file.set_offset(original_offset);
	return ret;
}

static int do_sys_access(UserPtr<const char*> pathname_ptr, int mode) {
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;
	if (!m_file_contents.count(pathname))
		return -EACCES;
	if ((mode & W_OK) || (mode & X_OK)) {
		printf_once("access %s, mode %d, denying\n", pathname.c_str(), mode);
		return -EACCES;
	}
	// It's asking for R_OK or F_OK
	return 0;
}

static ssize_t do_sys_write(int fd, UserPtr<const void*> buf, size_t count) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	return m_open_files[fd].write(buf, count);
}

static int do_sys_stat(UserPtr<const char*> pathname_ptr,
                       UserPtr<struct stat*> stat_ptr)
{
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;
	ASSERT(m_file_contents.count(pathname), "unknown %s", pathname.c_str());
	const iovec& iov = m_file_contents[pathname];
	return File::stat_regular(stat_ptr, iov.iov_len, (inode_t)iov.iov_base);
}

static int do_sys_fstat(int fd, UserPtr<struct stat*> stat_ptr) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	return m_open_files[fd].stat(stat_ptr);
}

static off_t do_sys_lseek(int fd, off_t offset, int whence) {
	// We use signed types here, as the syscall does, but we use unsigned types
	// in File. The syscall fails if the resulting offset is negative, so
	// there isn't any problem about that
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	File& file = m_open_files[fd];
	off_t ret;
	switch (whence) {
		case SEEK_SET:
			ret = offset;
			break;

		case SEEK_CUR:
			ret = file.offset() + offset;
			break;

		case SEEK_END:
			ret = file.size() + offset;
			break;

		default:
			TODO
	}
	if (ret < 0)
		return -EINVAL;
	file.set_offset(ret);
	return ret;
}

static int do_sys_close(int fd) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	//m_open_files.erase(fd); // ADAPTACIÓN STL
	m_open_files.erase({fd, m_open_files[fd]});
	return 0;
}

static uintptr_t do_sys_brk(uintptr_t addr) {
	dbgprintf("trying to set brk to %p, current is %p\n", addr, m_brk);
	if (addr < m_min_brk)
		return m_brk;

	uintptr_t next_page = PAGE_CEIL(m_brk);
	uintptr_t cur_page  = m_brk & PTL1_MASK;
	if (addr > next_page) {
		// We have to allocate space. First check if range is valid, and then
		// check if we have enough free memory. Don't do it the other way round,
		// as walking the page table in is_range_free allocates page table
		// directories.
		size_t sz = PAGE_CEIL(addr - next_page);
		uint64_t flags = PDE64_USER | PDE64_RW;

		if (!Mem::Virt::is_range_free((void*)next_page, sz)) {
			//printf_once("WARNING: brk range OOB allocating %lu\n", sz);
			return m_brk;
		}

		if (!Mem::Virt::enough_free_memory(sz)) {
			return m_brk;
		}

		Mem::Virt::alloc((void*)next_page, sz, flags);

	} else if (addr <= cur_page) {
		// Free space
		uintptr_t addr_next_page = PAGE_CEIL(addr);
		Mem::Virt::free((void*)addr_next_page, next_page - addr_next_page);
	}

	dbgprintf("brk set to %p\n", addr);
	m_brk = addr;
	return m_brk;
}

static uint64_t do_sys_uname(UserPtr<struct new_utsname*> uname_ptr) {
	constexpr static struct new_utsname uname = {
		"Linux",                                              // sysname
		"pep1t0",                                             // nodename
		"5.8.0-43-generic",                                   // release
		"#49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021", // version
		"x86_64"                                              // machine
	};
	return (copy_to_user(uname_ptr, &uname) ? 0 : -EFAULT);
}

static ssize_t do_sys_readlink(UserPtr<const char*> pathname_ptr,
                               UserPtr<char*> buf, size_t bufsize)
{
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;
	ASSERT(pathname == "/proc/self/exe", "not implemented %s", pathname.c_str());

	// TODO: size_t doesn't fit in ssize_t
	// Readlink does not append a null byte to buf
	size_t size = min(m_elf_path.size(), bufsize);
	return (copy_to_user(buf, m_elf_path.c_str(), size) ? size : -EFAULT);
}

static int do_sys_ioctl(int fd, uint64_t request, uint64_t arg) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO) {
		// We hold the whole struct termios2, but guest may want just a
		// struct termios
		bool success;
		if (request == TCGETS) {
			success = copy_to_user(UserPtr<struct termios*>(arg),
			                       (struct termios*)&m_term);
		} else if (request == TCGETS2) {
			success = copy_to_user(UserPtr<struct termios2*>(arg), &m_term);
		} else TODO;
		return (success ? 0 : -EFAULT);
	}
	ASSERT(false, "TODO ioctl, fd: %d, request: %p, arg: %p", fd, request, arg);
	return 0;
}

static int do_sys_fcntl(int fd, int cmd, unsigned long arg) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	File& file = m_open_files[fd];
	uint64_t ret = 0;
	uint32_t flags;
	switch (cmd) {
		// There's only one flag defined for F_GETFD and F_SETFD: FD_CLOEXEC.
		// It can also be specified when opening, with O_CLOEXEC.
		// For simplicity, save it as O_CLOEXEC
		case F_GETFD:
			ret = (file.flags() & O_CLOEXEC ? FD_CLOEXEC : 0);
			break;
		case F_SETFD:
			flags = file.flags();
			if (arg & FD_CLOEXEC)
				flags |= O_CLOEXEC;
			file.set_flags(flags);
			ret = 0;
			break;
		default:
			ASSERT(false, "TODO cmd = %d", cmd);
	}
	return ret;
}

uint64_t prot_to_page_flags(int prot) {
	ASSERT(!(prot & PROT_GROWSDOWN) && !(prot & PROT_GROWSUP), "prot: %d", prot);
	uint64_t page_flags = PDE64_USER;
	if (prot == PROT_NONE)
		page_flags |= PDE64_PROTNONE;
	else {
		// There's no way of having writable but not readable pages
		if (prot & PROT_WRITE)
			page_flags |= PDE64_RW;
		if (!(prot & PROT_EXEC))
			page_flags |= PDE64_NX;
	}
	return page_flags;
}

static uintptr_t do_sys_mmap(UserPtr<void*> addr, size_t length, int prot,
                             int flags, int fd, size_t offset)
{
	dbgprintf("mmap(%p, %ld, 0x%x, 0x%x, %d, %p)\n", addr, length, prot,
	          flags, fd, offset);
	ASSERT(fd == -1 || m_open_files.count(fd), "not open fd: %d", fd);

	// We're not supporting multiple threads, so MAP_SHARED can be safely
	// removed
	if (flags & MAP_SHARED) {
		flags &= ~MAP_SHARED;
		//printf_once("REMOVING MAP SHARED\n");
	}

	int supported_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE | MAP_FIXED;
	ASSERT((flags & supported_flags) == flags, "unsupported flags 0x%x", flags);

	// Parse perms
	uint64_t page_flags = prot_to_page_flags(prot);
	if (!(prot & PROT_WRITE) && fd != -1)
		page_flags |= PDE64_RW; // read only file: map as writable first

	// Round length to upper page boundary and check if we have enough memory
	size_t length_upper = PAGE_CEIL(length);
	if (!Mem::Virt::enough_free_memory(length_upper))
		return -ENOMEM;

	// Allocate memory
	void* ret;
	if (flags & MAP_FIXED) {
		ASSERT(addr, "MAP_FIXED with no addr");
		ret = addr.ptr();
		Mem::Virt::alloc(ret, length_upper, page_flags);
	} else {
		ret = Mem::Virt::alloc(length_upper, page_flags);
	}

	// If a file descriptor was specified, copy its content to memory
	if (fd != -1) {
		const File& f = m_open_files[fd];
		// User seems to be allowed to map beyond the file limits (when
		// offset + length > f.size()). Let's see if offset > f.size() is
		// supposed to be allowed.
		ASSERT(offset <= f.size(), "offset OOB: %p / %p", offset, f.size());
		memcpy(ret, f.buf() + offset, min(f.size() - offset, length));

		// If it was read only, remove write permissions after copying content
		if (!(prot & PROT_WRITE)) {
			page_flags &= ~PDE64_RW;
			Mem::Virt::set_flags(ret, length_upper, page_flags);
		}
	}

	return (uintptr_t)ret;
}

static int do_sys_munmap(UserPtr<void*> addr, size_t length) {
	if (!addr || !length)
		return -EINVAL;
	// Round length to upper page boundary
	length = PAGE_CEIL(length);
	Mem::Virt::free(addr.ptr(), length);
	return 0;
}

static int do_sys_mprotect(UserPtr<void*> addr, size_t length, int prot) {
	uint64_t page_flags = prot_to_page_flags(prot);
	Mem::Virt::set_flags(addr.ptr(), length, page_flags);
	return 0;
}

static int do_sys_prlimit(pid_t pid, int resource,
                          UserPtr<const struct rlimit*> new_limit_ptr,
                          UserPtr<struct rlimit*> old_limit_ptr)
{
	ASSERT(pid == MY_PID, "TODO pid %d", pid);
	if (old_limit_ptr) {
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

	if (new_limit_ptr) {
		switch (resource) {
			case RLIMIT_CORE:
				break;
			default:
				ASSERT(false, "TODO set limit %d", resource);
		}
	}
	return 0;
}

static int do_sys_sysinfo(UserPtr<struct sysinfo*> info_ptr) {
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

static int do_sys_tgkill(int tgid, int tid, int sig) {
	if (sig == SIGABRT && tgid == MY_PID && tid == MY_PID) {
		FaultInfo fault = {
			.type = FaultInfo::AssertionFailed,
			.rip = m_user_regs->rip
		};
		hc_fault(&fault);
	}
	TODO
	return 0;
}

static int do_sys_clock_gettime(clockid_t clock_id,
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
uint64_t handle_syscall(int nr, uint64_t arg0, uint64_t arg1, uint64_t arg2,
                        uint64_t arg3, uint64_t arg4, uint64_t arg5, Regs* regs)
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
			ret = 1234;
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

		default:
			hc_print_stacktrace(regs->rsp, regs->rip, regs->rbp);
			die("Unimplemented syscall: %s (%lld)\n", syscall_str[nr], nr);
	}

	dbgprintf("<-- syscall: %s returned 0x%lx\n", syscall_str[nr], ret);
	return ret;
}
