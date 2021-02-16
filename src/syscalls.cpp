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
#include <sys/ioctl.h>
#include "vm.h"
#include "syscall_str.h"
#include "common.h"

using namespace std;

uint64_t Vm::do_sys_arch_prctl(int code, vaddr_t addr) {
	uint64_t ret = 0;
	switch (code) {
		case ARCH_SET_FS:
			m_sregs->fs.base = addr;
			break;
		case ARCH_SET_GS:
			m_sregs->gs.base = addr;
			break;
		case ARCH_GET_FS:
			m_mmu.write<vaddr_t>(addr, m_sregs->fs.base);
			break;
		case ARCH_GET_GS:
			m_mmu.write<vaddr_t>(addr, m_sregs->gs.base);
			break;
		default:
			ret = -1;
	};

	if (code == ARCH_SET_FS || code == ARCH_SET_GS)
		set_sregs_dirty();

	return ret;
}

uint64_t Vm::do_sys_openat(int dirfd, vaddr_t pathname_addr, int flags,
                           mode_t mode)
{
	string pathname = m_mmu.read_string(pathname_addr);
	ASSERT(m_file_contents.count(pathname), "openat: unknown %s", pathname.c_str());
	ASSERT(dirfd == AT_FDCWD, "openat: %s dirfd %d", pathname.c_str(), dirfd);
	ASSERT(!((flags & O_WRONLY) || (flags & O_RDWR)),
	       "open: %s with write permisions", pathname.c_str());

	// Find unused fd
	int fd = 3;
	while (m_open_files.count(fd))
		fd++;

	// Create file
	struct iovec buf = m_file_contents[pathname];
	m_open_files[fd] = File(flags, (const char*)buf.iov_base, buf.iov_len);
	return fd;
}

uint64_t Vm::do_sys_writev(int fd, vaddr_t iov_addr, int iovcnt) {
	ASSERT(m_open_files.count(fd), "writev: not open fd: %d", fd);
	uint64_t ret  = 0;
	File&    file = m_open_files[fd];

	// Read iovec structs from guest memory
	struct iovec iov[iovcnt];
	m_mmu.read_mem(&iov, iov_addr, iovcnt * sizeof(struct iovec));

	// Write each iovec to file
	for (int i = 0; i < iovcnt; i++) {
		ret += file.write((vaddr_t)iov[i].iov_base, iov[i].iov_len, m_mmu);
	}
	return ret;
}

uint64_t Vm::do_sys_read(int fd, vaddr_t buf_addr, vsize_t count) {
	ASSERT(m_open_files.count(fd), "read: not open fd: %d", fd);
	return m_open_files[fd].read(buf_addr, count, m_mmu);
}

uint64_t Vm::do_sys_pread64(int fd, vaddr_t buf_addr, vsize_t count,
                            off_t offset)
{
	ASSERT(m_open_files.count(fd), "pread64: not open fd: %d", fd);
	ASSERT(offset >= 0, "pread64: negative offset on fd %d: %ld", fd, offset);

	// Change offset, read and restore offset
	File& file = m_open_files[fd];
	vsize_t original_offset = file.offset();
	file.set_offset(offset);
	uint64_t ret = file.read(buf_addr, count, m_mmu);
	file.set_offset(original_offset);
	return ret;
}

uint64_t Vm::do_sys_access(vaddr_t pathname_addr, int mode) {
	TODO
}

uint64_t Vm::do_sys_write(int fd, vaddr_t buf_addr, vsize_t count) {
	ASSERT(m_open_files.count(fd), "write: not open fd: %d", fd);
	return m_open_files[fd].write(buf_addr, count, m_mmu);
}

uint64_t Vm::do_sys_stat(vaddr_t pathname_addr, vaddr_t stat_addr) {
	string pathname = m_mmu.read_string(pathname_addr);
	ASSERT(m_file_contents.count(pathname), "stat: unknown %s", pathname.c_str());
	stat_regular(stat_addr, m_file_contents[pathname].iov_len, m_mmu);
	return 0;
}

uint64_t Vm::do_sys_fstat(int fd, vaddr_t stat_addr) {
	ASSERT(m_open_files.count(fd), "fstat: not open fd: %d", fd);
	m_open_files[fd].stat(stat_addr, m_mmu);
	return 0;
}

uint64_t Vm::do_sys_lseek(int fd, off_t offset, int whence) {
	// We use signed types here, as the syscall does, but we use unsigned types
	// in File. The syscall fails if the resulting offset is negative, so
	// there isn't any problem about that
	ASSERT(m_open_files.count(fd), "lseek: not open fd: %d", fd);
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
	ASSERT(ret >= 0, "lseek: set negative offset: %ld", offset);
	file.set_offset(ret);
	return ret;
}

uint64_t Vm::do_sys_close(int fd) {
	ASSERT(m_open_files.count(fd), "close: not open fd: %d", fd);
	m_open_files.erase(fd);
	return 0;
}

uint64_t Vm::do_sys_brk(vaddr_t addr) {
	return (m_mmu.set_brk(addr) ? addr : m_mmu.brk());
}

uint64_t Vm::do_sys_uname(vaddr_t buf_addr) {
	struct utsname uname = {
		"Linux",                                              // sysname
		"pep1t0",                                             // nodename
		"5.8.0-43-generic",                                   // release
		"#49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021", // version
		"x86_64"                                              // machine
	};
	m_mmu.write_mem(buf_addr, &uname, sizeof(uname));
	return 0;
}

uint64_t Vm::do_sys_readlink(vaddr_t pathname_addr, vaddr_t buf_addr,
                             vsize_t bufsize)
{
	string pathname = m_mmu.read_string(pathname_addr);
	ASSERT(pathname == "/proc/self/exe",
	       "readlink: not implemented %s", pathname.c_str());

	// Get path, convert it to absolute and write it to memory
	char abspath[PATH_MAX];
	ERROR_ON(!realpath(m_elf.path().c_str(), abspath), "readlink: realpath");
	uint64_t ret = min(bufsize, strlen(abspath));
	m_mmu.write_mem(buf_addr, abspath, ret);
	return ret;
}

uint64_t Vm::do_sys_ioctl(int fd, uint64_t request, uint64_t arg) {
	ASSERT(m_open_files.count(fd), "ioctl: not open fd: %d", fd);
	TODO
	return 0;
}

void Vm::handle_syscall() {
	uint64_t ret = 0;
	dbgprintf("--> syscall: %s\n", syscall_str[m_regs->rax]);
	switch (m_regs->rax) {
		case SYS_openat:
			ret = do_sys_openat(m_regs->rdi, m_regs->rsi, m_regs->rdx, m_regs->r10);
			break;
		case SYS_read:
			ret = do_sys_read(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case SYS_pread64:
			ret = do_sys_pread64(m_regs->rdi, m_regs->rsi, m_regs->rdx, m_regs->r10);
			break;
		case SYS_write:
			ret = do_sys_write(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case SYS_writev:
			ret = do_sys_writev(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case SYS_access:
			ret = do_sys_access(m_regs->rdi, m_regs->rsi);
			break;
		case SYS_lseek:
			ret = do_sys_lseek(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case SYS_close:
			ret = do_sys_close(m_regs->rdi);
			break;
		case SYS_brk:
			ret = do_sys_brk(m_regs->rdi);
			break;
		case SYS_exit:
		case SYS_exit_group:
			m_running = false;
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
			ret = do_sys_arch_prctl(m_regs->rdi, m_regs->rsi);
			break;
		case SYS_uname:
			ret = do_sys_uname(m_regs->rdi);
			break;
		case SYS_readlink:
			ret = do_sys_readlink(m_regs->rdi, m_regs->rsi, m_regs->rdx);
			break;
		case SYS_mprotect:
			ret = 0;
			break;
		case SYS_fstat:
			ret = do_sys_fstat(m_regs->rdi, m_regs->rsi);
			break;
		case SYS_stat:
			ret = do_sys_stat(m_regs->rdi, m_regs->rsi);
			break;
		case SYS_ioctl:
			ret = do_sys_ioctl(m_regs->rdi, m_regs->rsi, m_regs->rdx);
		default:
			dump_regs();
			die("Unimplemented syscall: %s (%lld)\n", syscall_str[m_regs->rax],
			    m_regs->rax);
	}

	dbgprintf("<-- syscall: %s returned %lX\n", syscall_str[m_regs->rax], ret);
	m_regs->rax = ret;
	set_regs_dirty();
}