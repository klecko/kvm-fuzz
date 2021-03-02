#define _GNU_SOURCE
#include "common.h"
#include "libcpp.h"
#include "kernel.h"
#include "hypercalls.h"
#include "syscall_str.h"

#include <string>
#include <unistd.h>
#include <limits.h>
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <asm-generic/errno-base.h>

using namespace std;

const char* syscall_str[500];

uint64_t Kernel::do_sys_arch_prctl(int code, unsigned long addr) {
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

uint64_t Kernel::do_sys_openat(int dirfd, const char* pathname, int flags,
                               mode_t mode)
{
	string pathname_s(pathname);
	ASSERT(m_file_contents.count(pathname_s), "unknown %s", pathname);
	ASSERT(dirfd == AT_FDCWD, "%s dirfd %d", pathname, dirfd);
	ASSERT(!((flags & O_WRONLY) || (flags & O_RDWR)),
	       "%s with write permisions", pathname);

	// Find unused fd
	int fd = 3;
	while (m_open_files.count(fd))
		fd++;

	// Create file
	struct iovec buf = m_file_contents[pathname_s];
	m_open_files[fd] = File(flags, (const char*)buf.iov_base, buf.iov_len);
	return fd;
}

uint64_t Kernel::do_sys_writev(int fd, const struct iovec* iov, int iovcnt) {
	TODO
	/* ASSERT(m_open_files.count(fd), "writev: not open fd: %d", fd);
	uint64_t ret  = 0;
	File&    file = m_open_files[fd];

	// Read iovec structs from guest memory
	struct iovec iov[iovcnt];
	m_mmu.read_mem(&iov, iov_addr, iovcnt * sizeof(struct iovec));

	// Write each iovec to file
	for (int i = 0; i < iovcnt; i++) {
		ret += file.write((vaddr_t)iov[i].iov_base, iov[i].iov_len);
	}
	return ret; */
}

uint64_t Kernel::do_sys_read(int fd, void* buf, size_t count) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	return m_open_files[fd].read(buf, count);
}

uint64_t Kernel::do_sys_pread64(int fd, void* buf, size_t count, off_t offset) {
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

uint64_t Kernel::do_sys_access(const char* pathname, int mode) {
	TODO
}

uint64_t Kernel::do_sys_write(int fd, const void* buf, size_t count) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	return m_open_files[fd].write(buf, count);
}

uint64_t Kernel::do_sys_stat(const char* pathname, struct stat* statbuf) {
	string pathname_s(pathname);
	ASSERT(m_file_contents.count(pathname_s), "unknown %s", pathname);
	stat_regular(statbuf, m_file_contents[pathname_s].iov_len);
	return 0;
}

uint64_t Kernel::do_sys_fstat(int fd, struct stat* statbuf) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	m_open_files[fd].stat(statbuf);
	return 0;
}

uint64_t Kernel::do_sys_lseek(int fd, off_t offset, int whence) {
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

uint64_t Kernel::do_sys_close(int fd) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	//m_open_files.erase(fd); // ADAPTACIÓN STL
	m_open_files.erase({fd, m_open_files[fd]});
	return 0;
}

uint64_t Kernel::do_sys_brk(void* addr) {
	dbgprintf("trying to set brk to 0x%lx\n", addr);
	if (addr < m_min_brk)
		return (uint64_t)m_brk;

	// Allocate space if needed
	// Too many castings. There must be a better way to do this
	uintptr_t next_page = ((uintptr_t)m_brk + 0xFFF) & ~0xFFF;
	if ((uintptr_t)addr > next_page) {
		size_t sz = ((uintptr_t)addr - next_page + 0xFFF) & ~0xFFF;
		hc_mmap((void*)next_page, sz, PDE64_RW | PDE64_USER,
		        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED);
	}

	dbgprintf("brk set to 0x%lx\n", addr);
	m_brk = addr;

	return (uint64_t)m_brk;
}

uint64_t Kernel::do_sys_uname(struct utsname* buf) {
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

uint64_t Kernel::do_sys_readlink(const char* pathname, char* buf,
                                 size_t bufsize)
{
	string pathname_s(pathname);
	ASSERT(pathname_s == "/proc/self/exe", "not implemented %s", pathname);

	// Readlink does not append a null byte to buf
	size_t size = min(m_elf_path.size(), bufsize);
	memcpy(buf, m_elf_path.c_str(), size);
	return size;
}

uint64_t Kernel::do_sys_ioctl(int fd, uint64_t request, uint64_t arg) {
	ASSERT(m_open_files.count(fd), "not open fd: %d", fd);
	TODO
	return 0;
}

uint64_t Kernel::do_sys_fcntl(int fd, int cmd, unsigned long arg) {
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

uint64_t Kernel::do_sys_mmap(void* addr, size_t length, int prot, int flags,
	                         int fd, off_t offset)
{
	// We'll remove this checks little by little :)
	ASSERT(fd == -1, "fd %d", fd);
	ASSERT(offset == 0, "offset %ld", offset);
	uint64_t page_flags = PDE64_USER;
	if (prot & PROT_WRITE)
		page_flags |= PDE64_RW;
	if (!(prot & PROT_EXEC))
		page_flags |= PDE64_NX;
	return (uint64_t)hc_mmap(addr, length, page_flags, flags);
	/* ASSERT(addr == 0, "mmap: not null addr %lx", addr);
	ASSERT((length & PTL1_MASK) == length, "mmap: not aligned length %lx", length);
	ASSERT((flags & MAP_TYPE) == MAP_PRIVATE, "mmap: shared mmaping");
	ASSERT((flags & ~MAP_TYPE) == MAP_ANONYMOUS, "mmap: flags");
	ASSERT(fd == -1, "mmap: fd %d", fd);
	ASSERT(offset == 0, "mmap: offset %ld", offset);

	uint64_t mmu_flags = 0;
	if (prot & PROT_WRITE)
		mmu_flags |= PDE64_RW;
	if (!(prot & PROT_EXEC))
		mmu_flags |= PDE64_NX;
	return m_mmu.alloc(length, mmu_flags); */
}

uint64_t Kernel::do_sys_munmap(void* addr, size_t length) {
	// TODO
	return 0;
}

uint64_t Kernel::do_sys_mprotect(void* addr, size_t length, int prot) {
	TODO;
	/* ASSERT(!(prot & PROT_GROWSDOWN) && !(prot & PROT_GROWSUP), "mprotect todo");
	uint64_t flags = 0;
	if (prot & PROT_WRITE)
		flags |= PDE64_RW;
	if (!(prot & PROT_EXEC))
		flags |= PDE64_NX;

	m_mmu.set_flags(addr, length, flags); */
	return 0;
}

uint64_t Kernel::do_sys_prlimit(pid_t pid, int resource,
                                const struct rlimit* new_limit,
                                struct rlimit* old_limit)
{
	ASSERT(pid == 0, "TODO pid %d", pid);
	ASSERT(new_limit == NULL, "TODO set limit");
	struct rlimit limit;
	switch (resource) {
		case RLIMIT_NOFILE:
			limit.rlim_cur = 1024;
			limit.rlim_max = 1048576;
			break;
		default:
			TODO
	}
	memcpy(old_limit, &limit, sizeof(limit));
	return 0;
}

uint64_t Kernel::do_sys_sysinfo(struct sysinfo* info) {
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

/* void print_syscalls(int n[500]) {
	int sum = 0;
	for (int i = 0; i < 500; i++) {
		if (n[i]) {
			printf("%s: %d\n", syscall_str[i], n[i]);
			sum += n[i];
		}
	}
	printf("total: %d\n", sum);
} */

uint64_t Kernel::handle_syscall(int nr, uint64_t arg0, uint64_t arg1, uint64_t arg2,
                                uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
	dbgprintf("--> syscall: %s\n", syscall_str[nr]);
	uint64_t ret = 0;
	switch (nr) {
		case SYS_openat:
			ret = do_sys_openat(arg0, (const char*)arg1, arg2, arg3);
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
			ret = do_sys_brk((void*)arg0);
			break;
		case SYS_exit:
		case SYS_exit_group:
			//dbgprintf("end run --------------------------------\n\n");
			hc_end_run();
			//print_syscalls(n);
			break;
		case SYS_getuid:
			ret = 0;
			break;
		case SYS_getgid:
			ret = 0;
			break;
		case SYS_geteuid:
			ret = 0;
			break;
		case SYS_getegid:
			ret = 0;
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
			ret = 0; // TODO
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
		default:
			//dump_regs();
			TODO
			//die("Unimplemented syscall: %s (%lld)\n", syscall_str[m_regs->rax],
			//    m_regs->rax);
	}

	dbgprintf("<-- syscall: %s returned 0x%lx\n", syscall_str[nr], ret);
	return ret;
}