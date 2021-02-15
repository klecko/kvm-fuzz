#ifndef _VM_H
#define _VM_H

#include <iostream>
#include <vector>
#include <unordered_map>
#include <sys/uio.h>
#include "stats.h"
#include "mmu.h"
#include "file.h"
#include "common.h"
#include "kvm_aux.h"

void init_kvm();

class Vm {
public:
	Vm(vsize_t mem_size, const std::string& filepath,
	   const std::vector<std::string>& argv);
	Vm(const Vm& other);

	void reset(const Vm& other, Stats& stats);
	psize_t memsize() const;
	void run(Stats& stats);
	void run_until(vaddr_t pc, Stats& stats);
	void set_breakpoint(vaddr_t addr);
	void remove_breakpoint(vaddr_t addr);

	// Associate `filename` with `content` to emulate file operations in the
	// guest. String `content` shouldn't be modified and it could be shared
	// by all threads
	void set_file(const std::string& filename, const std::string& content);
	void dump_regs();
	void dump_memory() const;
	void dump_memory(psize_t len) const;

private:
	int vm_fd;
	struct {
		int fd;
		struct kvm_run* run;
	} vcpu;
	kvm_regs* regs;
	kvm_sregs* sregs;
	ElfParser elf;
	ElfParser* interpreter;
	Mmu mmu;
	bool running;
	std::unordered_map<vaddr_t, uint8_t> breakpoints_original_bytes;

	// Open files indexed by file descriptor
	std::unordered_map<int, File> open_files;

	// Files contents indexed by filename
	std::unordered_map<std::string, struct iovec> file_contents;

	void setup();
	void setup_kvm();
	void load_elf(const std::vector<std::string>& argv);
	void vm_err(const std::string& err);

	void handle_syscall();
	uint64_t do_sys_arch_prctl(int code, vaddr_t addr);
	uint64_t do_sys_openat(int dirfd, vaddr_t pathname_addr, int flags,
	                       mode_t mode);
	uint64_t do_sys_writev(int fd, vaddr_t iov_addr, int iovcnt);
	uint64_t do_sys_read(int fd, vaddr_t buf_addr, vsize_t count);
	uint64_t do_sys_pread64(int fd, vaddr_t buf_addr, vsize_t count,
	                        off_t offset);
	uint64_t do_sys_access(vaddr_t pathname_addr, int mode);
	uint64_t do_sys_write(int fd, vaddr_t buf_addr, vsize_t count);
	uint64_t do_sys_stat(vaddr_t pathname_addr, vaddr_t stat_addr);
	uint64_t do_sys_fstat(int fd, vaddr_t stat_addr);
	uint64_t do_sys_lseek(int fd, off_t offset, int whence);
	uint64_t do_sys_close(int fd);
	uint64_t do_sys_brk(vaddr_t addr);
	uint64_t do_sys_uname(vaddr_t buf_addr);
	uint64_t do_sys_readlink(vaddr_t pathname_addr, vaddr_t buf_addr,
	                         vsize_t bufsize);
	uint64_t do_sys_ioctl(int fd, uint64_t request, uint64_t arg);
};

#endif