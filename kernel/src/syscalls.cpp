#define _GNU_SOURCE
#include "syscalls.h"
#include "common.h"
#include "kernel.h"
#include "syscall_str.h"
#include "asm.h"
#include "mem.h"
#include "string"

// Linux
#include <asm/prctl.h>
#include <sys/fcntl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <asm-generic/errno-base.h>

using namespace std;

const char* syscall_str[500];

static uint64_t do_sys_arch_prctl(int code, unsigned long addr) {
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
			ret = -1;
	};

	//TODO
	return ret;
}

static uint64_t do_sys_openat(int dirfd, const char* pathname, int flags,
                              mode_t mode)
{
	string pathname_s(pathname);
	ASSERT(dirfd == AT_FDCWD, "%s dirfd %d", pathname, dirfd);
	dbgprintf("opening %s\n", pathname);

	// Find unused fd
	int fd = 3;
	while (m_open_files.count(fd))
		fd++;

	// Create file
	if (pathname_s == "-") {
		m_open_files[fd] = FileStdout();
	} else {
		ASSERT(m_file_contents.count(pathname_s), "unknown file '%s'", pathname);
		ASSERT(!((flags & O_WRONLY) || (flags & O_RDWR)),
			"%s with write permisions", pathname);
		struct iovec buf = m_file_contents[pathname_s];
		m_open_files[fd] = File(flags, (const char*)buf.iov_base, buf.iov_len);
	}
	return fd;
}

static uint64_t do_sys_open(const char* pathname, int flags, mode_t mode) {
	return do_sys_openat(AT_FDCWD, pathname, flags, mode);
}

static uint64_t do_sys_writev(int fd, const struct iovec* iov, int iovcnt) {
	ASSERT(m_open_files.count(fd), "writev: not open fd: %d", fd);
	uint64_t ret  = 0;
	File&    file = m_open_files[fd];

	// Write each iovec to file
	hc_print("WRITEV\n");
	for (int i = 0; i < iovcnt; i++) {
		// FIXME
		hc_print((const char*)iov[i].iov_base, iov[i].iov_len);
		ret += iov[i].iov_len; //file.write(iov[i].iov_base, iov[i].iov_len);
	}

	return ret;
}

static uint64_t do_sys_read(int fd, void* buf, size_t count) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	return m_open_files[fd].read(buf, count);
}

static uint64_t do_sys_pread64(int fd, void* buf, size_t count, off_t offset) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	ASSERT(offset >= 0, "negative offset on fd %d: %ld", fd, offset);

	// Change offset, read and restore offset
	File& file = m_open_files[fd];
	size_t original_offset = file.offset();
	file.set_offset(offset);
	uint64_t ret = file.read(buf, count);
	file.set_offset(original_offset);
	return ret;
}

static uint64_t do_sys_access(const char* pathname, int mode) {
	if (!m_file_contents.count(pathname)) {
		return -ENOENT;
	}
	ASSERT(false, "access: %s 0x%x\n", pathname, mode);
	return 0;
}

static uint64_t do_sys_write(int fd, const void* buf, size_t count) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	return m_open_files[fd].write(buf, count);
}

static uint64_t do_sys_stat(const char* pathname, struct stat* statbuf) {
	string pathname_s(pathname);
	ASSERT(m_file_contents.count(pathname_s), "unknown %s", pathname);
	const iovec& iov = m_file_contents[pathname_s];
	stat_regular(statbuf, iov.iov_len, (unsigned long)iov.iov_base);
	return 0;
}

static uint64_t do_sys_fstat(int fd, struct stat* statbuf) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	m_open_files[fd].stat(statbuf);
	return 0;
}

static uint64_t do_sys_lseek(int fd, off_t offset, int whence) {
	// We use signed types here, as the syscall does, but we use unsigned types
	// in File. The syscall fails if the resulting offset is negative, so
	// there isn't any problem about that
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	File& file = m_open_files[fd];
	int64_t ret;
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

static uint64_t do_sys_close(int fd) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	//m_open_files.erase(fd); // ADAPTACIÓN STL
	m_open_files.erase({fd, m_open_files[fd]});
	return 0;
}

static uint64_t do_sys_brk(uintptr_t addr) {
	dbgprintf("trying to set brk to %p, current is %p\n", addr, m_brk);
	if (addr < m_min_brk)
		return m_brk;

	uintptr_t next_page = PAGE_CEIL(m_brk);
	uintptr_t cur_page  = m_brk & PTL1_MASK;
	if (addr > next_page) {
		// We have to allocate space. First check if range is valid
		size_t sz = PAGE_CEIL(addr - next_page);
		uint64_t flags = PDE64_USER | PDE64_RW;
		if (Mem::Virt::is_range_allocated((void*)next_page, sz)) {
			//printf_once("WARNING: brk range OOB allocating %lu\n", sz);
			return m_brk;
		}

		if (!Mem::Virt::alloc((void*)next_page, sz, flags, false)) {
			//printf_once("WARNING: brk OOM allocating %lu\n", sz);
			return m_brk;
		}
	} else if (addr <= cur_page) {
		// Free space
		uintptr_t addr_next_page = PAGE_CEIL(addr);
		Mem::Virt::free((void*)addr_next_page, next_page - addr_next_page);
	}

	dbgprintf("brk set to %p\n", addr);
	m_brk = addr;
	return m_brk;
}

static uint64_t do_sys_uname(struct utsname* buf) {
	struct utsname uname = {
		"Linux",                                              // sysname
		"pep1t0",                                             // nodename
		"5.8.0-43-generic",                                   // release
		"#49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021", // version
		"x86_64"                                              // machine
	};
	memcpy(buf, &uname, sizeof(uname));
	return 0;
}

static uint64_t do_sys_readlink(const char* pathname, char* buf,
                                size_t bufsize)
{
	string pathname_s(pathname);
	ASSERT(pathname_s == "/proc/self/exe", "not implemented %s", pathname);

	// Readlink does not append a null byte to buf
	size_t size = min(m_elf_path.size(), bufsize);
	memcpy(buf, m_elf_path.c_str(), size);
	return size;
}

static uint64_t do_sys_ioctl(int fd, uint64_t request, uint64_t arg) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	TODO
	return 0;
}

static uint64_t do_sys_fcntl(int fd, int cmd, unsigned long arg) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	File& file = m_open_files[fd];
	uint64_t ret = 0;
	uint32_t flags;
	switch (cmd) {
		// There's only one flag defined for this: FD_CLOEXEC.
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

static uint64_t do_sys_mmap(void* addr, size_t length, int prot, int flags,
                            int fd, size_t offset)
{
	// We'll remove this checks little by little :)
	dbgprintf("mmap(%p, %ld, 0x%x, 0x%x, %d, %p)\n", addr, length, prot,
	          flags, fd, offset);
	ASSERT(fd == -1 || m_open_files.count(fd), "not open fd: %d", fd);

	if (flags & MAP_SHARED) {
		flags &= ~MAP_SHARED;
		//printf_once("REMOVING MAP SHARED\n");
	}

	int supported_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE | MAP_FIXED;
	ASSERT((flags & supported_flags) == flags, "flags 0x%x", flags);

	// Parse perms
	uint64_t page_flags = prot_to_page_flags(prot);
	if (!(prot & PROT_WRITE) && fd != -1)
		page_flags |= PDE64_RW; // read only file: map as writable first

	// Round length to upper page boundary
	size_t length_upper = PAGE_CEIL(length);

	// Allocate memory, handling OOM ourselves
	void* ret;
	if (flags & MAP_FIXED) {
		ASSERT(addr, "MAP_FIXED with no addr");
		ret = addr;
		if (!Mem::Virt::alloc(addr, length_upper, page_flags, false))
			ret = NULL;
	} else {
		ret = Mem::Virt::alloc(length_upper, page_flags, false);
	}
	if (ret == NULL) {
		//printf_once("WARNING: sys_mmap OOM allocating %lu bytes\n", length);
		return -ENOMEM;
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

	return (uint64_t)ret;
}

static uint64_t do_sys_munmap(void* addr, size_t length) {
	if (!addr)
		return -EINVAL;
	// Round length to upper page boundary
	length = PAGE_CEIL(length);
	Mem::Virt::free(addr, length);
	return 0;
}

static uint64_t do_sys_mprotect(void* addr, size_t length, int prot) {
	uint64_t page_flags = prot_to_page_flags(prot);
	Mem::Virt::set_flags(addr, length, page_flags);
	return 0;
}

static uint64_t do_sys_prlimit(pid_t pid, int resource,
                               const struct rlimit* new_limit,
                               struct rlimit* old_limit)
{
	ASSERT(pid == 0, "TODO pid %d", pid);
	if (old_limit) {
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
		memcpy(old_limit, &limit, sizeof(limit));
	}

	if (new_limit) {
		switch (resource) {
			case RLIMIT_CORE:
				break;
			default:
				ASSERT(false, "TODO set limit %d", resource);
		}
	}
	return 0;
}

static uint64_t do_sys_sysinfo(struct sysinfo* info) {
	struct sysinfo sys = {
		.uptime    = 1234,
		.loads     = {102176, 105792, 94720},
		.totalram  = 32UL*1024*1024*1024,
		.freeram   = 26UL*1024*1024*1024,
		.sharedram = 1UL*1024*1024*1024,
		.bufferram = 1UL*1024*1024*1024,
		.totalswap = 2UL*1024*1024*1024,
		.freeswap  = 2UL*1024*1024*1024,
		.procs     = 1234,
		.totalhigh = 0,
		.freehigh  = 0,
		.mem_unit  = 1
	};
	memcpy(info, &sys, sizeof(sys));
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
	syscall_counts[nr]++;
	uint64_t ret = 0;
	switch (nr) {
		case SYS_openat:
			//hc_print_stacktrace(regs->rsp, regs->rip, regs->rbp);
			ret = do_sys_openat(arg0, (const char*)arg1, arg2, arg3);
			break;
		case SYS_open:
			ret = do_sys_open((const char*)arg0, arg1, arg2);
			break;
		case SYS_read:
			ret = do_sys_read(arg0, (void*)arg1, arg2);
			break;
		case SYS_pread64:
			ret = do_sys_pread64(arg0, (void*)arg1, arg2, arg3);
			break;
		case SYS_write:
			ret = do_sys_write(arg0, (const void*)arg1, arg2);
			break;
		case SYS_writev:
			ret = do_sys_writev(arg0, (const iovec*)arg1, arg2);
			{
				hc_print_stacktrace(regs->rsp, regs->rip, regs->rbp);
				// FaultInfo fault = {
				// 	.type = FaultInfo::Type::OutOfBoundsRead,
				// 	.rip = 1234,
				// };
				// hc_fault(&fault);
			}
			break;
		case SYS_access:
			ret = do_sys_access((const char*)arg0, arg1);
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
			ret = do_sys_uname((struct utsname*)arg0);
			break;
		case SYS_readlink:
			ret = do_sys_readlink((const char*)arg0, (char*)arg1, arg2);
			break;
		case SYS_mmap:
			ret = do_sys_mmap((void*)arg0, arg1, arg2, arg3, arg4, arg5);
			break;
		case SYS_munmap:
			ret = do_sys_munmap((void*)arg0, arg1);
			break;
		case SYS_mprotect:
			ret = do_sys_mprotect((void*)arg0, arg1, arg2);
			break;
		case SYS_fstat:
			ret = do_sys_fstat(arg0, (struct stat*)arg1);
			break;
		case SYS_stat:
			ret = do_sys_stat((const char*)arg0, (struct stat*)arg1);
			break;
		case SYS_ioctl:
			ret = do_sys_ioctl(arg0, arg1, arg2);
			break;
		case SYS_fcntl:
			ret = do_sys_fcntl(arg0, arg1, arg2);
			break;
		case SYS_prlimit64:
			ret = do_sys_prlimit(arg0, arg1, (const struct rlimit*)arg2,
			                     (struct rlimit*)arg3);
			break;
		case SYS_sysinfo:
			ret = do_sys_sysinfo((struct sysinfo*)arg0);
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
