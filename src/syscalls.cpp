#include <sys/syscall.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include "vm.h"
#include "syscall_str.h"
#include "common.h"


uint64_t Vm::do_sys_arch_prctl() {
	uint64_t ret = 0;
	switch (regs->rdi) {
		case ARCH_SET_FS:
			sregs->fs.base = regs->rsi;
			break;
		case ARCH_SET_GS:
			sregs->gs.base = regs->rsi;
			break;
		default:
			ret = -1;
	};

	if (ret == 0)
		vcpu.run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;

	return ret;
}

uint64_t Vm::do_sys_openat() {
	// FIXME
	const char* pathname = (char*)mmu.get(regs->rsi);
	printf("opening file %s\n", pathname);
	return syscall(SYS_openat, regs->rdi, pathname, regs->rdx, regs->r10);
	return -13;
}

uint64_t Vm::do_sys_writev() {
	uint64_t ret = 0;
	for (size_t i = 0; i < regs->rdx; i++) {
		struct iovec iov;
		mmu.read_mem(&iov, regs->rsi + i*sizeof(iovec), sizeof(iovec));
		char* buf = (char*)malloc(iov.iov_len);
		mmu.read_mem(buf, (vaddr_t)iov.iov_base, iov.iov_len);
		ret += write(regs->rdi, buf, iov.iov_len);
		free(buf);
	}
	return ret;
}

uint64_t Vm::do_sys_read() {
	void* buf = malloc(regs->rdx);
	uint64_t ret = syscall(SYS_read, regs->rdi, buf, regs->rdx);
	mmu.write_mem(regs->rsi, buf, ret);
	free(buf);
	return ret;
}

uint64_t Vm::do_sys_pread64() {
	void* buf = malloc(regs->rdx);
	uint64_t ret = syscall(SYS_pread64, regs->rdi, buf, regs->rdx, regs->r10);
	mmu.write_mem(regs->rsi, buf, ret);
	free(buf);
	return ret;
}

uint64_t Vm::do_sys_access() {
	// FIXME
	return syscall(SYS_access, mmu.get(regs->rdi), regs->rsi);
}

void Vm::handle_syscall() {
	uint64_t ret = 0;
	dbgprintf("syscall: %s\n", syscall_str[regs->rax]);
	switch (regs->rax) {
		case SYS_openat:
			ret = do_sys_openat();
			break;
		case SYS_read:
			ret = do_sys_read();
			break;
		case SYS_pread64:
			ret = do_sys_pread64();
			break;
		case SYS_write: // FIXME
			ret = syscall(SYS_write, regs->rdi, mmu.get(regs->rsi), regs->rdx);
			ret = regs->rdx;
			break;
		case SYS_writev:
			ret = do_sys_writev();
			break;
		case SYS_access:
			ret = do_sys_access();
			break;
		case SYS_brk:
			ret = (mmu.set_brk(regs->rdi) ? regs->rdi : mmu.get_brk());
			break;
		case SYS_exit:
		case SYS_exit_group:
			running = false;
			break;
		case SYS_getuid:
			ret = 0;
			break;
		case SYS_getgid:
			ret = 0;
			break;
		case SYS_geteuid:
			ret = 0; //syscall(SYS_geteuid);
			break;
		case SYS_getegid:
			ret = 0;
			break;
		case SYS_arch_prctl:
			ret = do_sys_arch_prctl();
			break;
		case SYS_uname: // FIXME
			ret = syscall(SYS_uname, mmu.get(regs->rdi));
			break;
		case SYS_readlink: // FIXME
			ret = syscall(SYS_readlink, mmu.get(regs->rdi),
			              mmu.get(regs->rsi), regs->rdx);
			break;
		case SYS_mprotect:
			ret = 0; // TODO
			break;
		case SYS_fstat: // FIXME
			ret = syscall(SYS_fstat, regs->rdi, mmu.get(regs->rsi));
			break;
		default:
			dump_regs();
			die("Unknown syscall: %lld\n", regs->rax);
	}

	dbgprintf("syscall: %s returned %lX\n", syscall_str[regs->rax], ret);
	regs->rax = ret;
	vcpu.run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
}