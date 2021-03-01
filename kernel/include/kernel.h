#ifndef _KERNEL_H
#define _KERNEL_H

#include <map>
#include <string>
#include <sys/uio.h>
#include "common.h"
#include "file.h"
#include "aux.h"

#define unordered_map map

class Kernel {
public:
	static void init();
	static void save_kernel_stack();
	static void save_user_stack();
	static void restore_kernel_stack();
	static void restore_user_stack();

private:
	// Saved kernel and user stack
	static void* m_kernel_stack;
	static void* m_user_stack;

	// Absolute path of the elf we're emulating
	static string m_elf_path;

	// User brk
	static void* m_brk;
	static void* m_min_brk;

	// Open files indexed by file descriptor
	static unordered_map<int, File> m_open_files;

	// Files contents indexed by filename
	static unordered_map<string, struct iovec> m_file_contents;

	static void wrmsr(unsigned int msr, uint64_t val);
	static uint64_t rdmsr(unsigned int msr);
	static void register_syscall();
	static void syscall_entry();
	static uint64_t _handle_syscall(uint64_t, uint64_t, uint64_t, uint64_t,
	                                uint64_t, uint64_t);
	static uint64_t handle_syscall(int, uint64_t, uint64_t, uint64_t, uint64_t,
	                               uint64_t, uint64_t);
	static uint64_t do_sys_arch_prctl(int code, unsigned long addr);
	static uint64_t do_sys_openat(int dirfd, const char* pathname, int flags,
	                       mode_t mode);
	static uint64_t do_sys_writev(int fd, const struct iovec* iov, int iovcnt);
	static uint64_t do_sys_read(int fd, void* buf, size_t count);
	static uint64_t do_sys_pread64(int fd, void* buf, size_t count, off_t offset);
	static uint64_t do_sys_access(const char* pathname, int mode);
	static uint64_t do_sys_write(int fd, const void* buf, size_t count);
	static uint64_t do_sys_stat(const char* pathname, struct stat* statbuf);
	static uint64_t do_sys_fstat(int fd, struct stat* statbuf);
	static uint64_t do_sys_lseek(int fd, off_t offset, int whence);
	static uint64_t do_sys_close(int fd);
	static uint64_t do_sys_brk(void* addr);
	static uint64_t do_sys_uname(struct utsname* buf);
	static uint64_t do_sys_readlink(const char* pathname, char* buf, size_t bufsize);
	static uint64_t do_sys_ioctl(int fd, unsigned long request, unsigned long arg);
	static uint64_t do_sys_mmap(void* addr, size_t length, int prot, int flags,
	                     int fd, off_t offset);
	static uint64_t do_sys_munmap(void* addr, size_t length);
	static uint64_t do_sys_mprotect(void* addr, size_t length, int prot);
	static uint64_t do_sys_fcntl(int fd, int cmd, unsigned long arg);
	static uint64_t do_sys_prlimit(pid_t pid, int resource,
	                        const struct rlimit* new_limit,
	                        struct rlimit* old_limit);
	static uint64_t do_sys_sysinfo(struct sysinfo* info);
};

#endif