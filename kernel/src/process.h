#ifndef _PROCESS_H
#define _PROCESS_H

#include "common.h"
#include "map"
#include "string"
#include "fs/file_description.h"
#include "mem/address_space.h"

#include "linux/resource.h"
#include "linux/uio.h"
#include "linux/sysinfo.h"
#include "others.h"

// Guest regs that syscall handler can read and modify
struct Regs {
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t rip;
};

class Process {
public:
	// Process();

	Process(const VmInfo& info);

	Process(const Process& other, unsigned long clone_flags);

	AddressSpace& space();
	const AddressSpace& space() const;

	void start_user(int argc, char** argv, const VmInfo& info);

	uint64_t handle_syscall(int nr, uint64_t, uint64_t, uint64_t, uint64_t,
	                        uint64_t, uint64_t, Regs* regs);

private:
	static int s_next_pid;
	static FileDescriptorTable& default_files();

	int m_pid;
	int m_tgid;
	AddressSpace m_space;

	FileDescriptorTable& m_files;
	string m_elf_path;
	uintptr_t m_brk;
	uintptr_t m_min_brk;
	Regs* m_user_regs;

	int available_fd();
	int child_return_from_clone();

	int do_sys_access(UserPtr<const char*>, int);
	int do_sys_openat(int, UserPtr<const char*>, int, mode_t);
	int do_sys_open(UserPtr<const char*>, int, mode_t);
	ssize_t do_sys_read(int, UserPtr<void*>, size_t);
	ssize_t do_sys_pread64(int, UserPtr<void*>, size_t, off_t);
	ssize_t do_sys_write(int, UserPtr<const void*>, size_t);
	ssize_t do_sys_writev(int, UserPtr<const struct iovec*>, int);
	int do_sys_stat(UserPtr<const char*>, UserPtr<struct stat*>);
	int do_sys_fstat(int, UserPtr<struct stat*>);
	off_t do_sys_lseek(int, off_t, int);
	int do_sys_dup(int);
	int do_sys_dup2(int, int);
	int do_sys_close(int);
	int do_sys_arch_prctl(int, uint64_t);
	uintptr_t do_sys_brk(uintptr_t);
	int do_sys_uname(UserPtr<struct new_utsname*>);
	ssize_t do_sys_readlink(UserPtr<const char*>, UserPtr<char*>, size_t);
	int do_sys_ioctl(int, uint64_t, uint64_t);
	int do_sys_fcntl(int, int, uint64_t);
	uintptr_t do_sys_mmap(UserPtr<void*>, size_t, int, int, int, size_t);
	int do_sys_munmap(UserPtr<void*>, size_t);
	int do_sys_mprotect(UserPtr<void*>, size_t, int);
	int do_sys_prlimit(pid_t, int, UserPtr<const rlimit*>, UserPtr<rlimit*>);
	int do_sys_sysinfo(UserPtr<struct sysinfo*>);
	int do_sys_tgkill(int, int, int);
	int do_sys_clock_gettime(clockid_t, UserPtr<struct timespec*>);
	int do_sys_getcwd(UserPtr<char*>, size_t);
	int do_sys_chdir(UserPtr<const char*>);
	int do_sys_socket(int, int, int);
	int do_sys_setsockopt(int, int, int, UserPtr<const void*>, socklen_t);
	int do_sys_bind(int, UserPtr<const struct sockaddr*>, socklen_t);
	int do_sys_listen(int, int);
	int do_sys_accept(int, UserPtr<struct sockaddr*>, UserPtr<socklen_t*>);
	int do_sys_getpeername(int, UserPtr<struct sockaddr*>, UserPtr<socklen_t*>);
	ssize_t do_sys_recvfrom(int, UserPtr<void*>, size_t, int,
	                        UserPtr<struct sockaddr*>, UserPtr<socklen_t*>);
	ssize_t do_sys_sendto(int, UserPtr<void*>, size_t, int,
	                      UserPtr<const struct sockaddr*>, socklen_t);
	ssize_t do_sys_sendfile(int, int, UserPtr<off_t*>, ssize_t);
	int do_sys_clone(unsigned long, UserPtr<void*>, UserPtr<int*>,
	                 UserPtr<int*>, unsigned long);
	int do_sys_clone3(UserPtr<struct clone_args*>, size_t size);
};

#endif