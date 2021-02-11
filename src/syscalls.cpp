#include <sys/syscall.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include "vm.h"
#include "common.h"

uint64_t Vm::do_sys_arch_prctl(const kvm_regs& regs) {
	uint64_t ret = 0;
	kvm_sregs sregs;
	ioctl_chk(vcpu.fd, KVM_GET_SREGS, &sregs);
	switch (regs.rdi) {
		case ARCH_SET_FS:
			sregs.fs.base = regs.rsi;
			break;
		case ARCH_SET_GS:
			sregs.gs.base = regs.rsi;
			break;
		default:
			ret = -1;
	};

	if (ret == 0)
		ioctl_chk(vcpu.fd, KVM_SET_SREGS, &sregs);

	return ret;
}

void Vm::handle_syscall() {
	uint64_t ret = 0;
	kvm_regs regs;
	ioctl_chk(vcpu.fd, KVM_GET_REGS, &regs);
	dbgprintf("Handling syscall %lld\n", regs.rax);
	switch (regs.rax) {
		case SYS_write:
			ret = syscall(SYS_write, regs.rdi, mmu.translate(regs.rsi), regs.rdx);
			break;
		case SYS_brk:
			ret = (mmu.set_brk(regs.rdi) ? regs.rdi : mmu.get_brk());
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
			ret = do_sys_arch_prctl(regs);
			break;
		case SYS_uname:
			ret = syscall(SYS_uname, mmu.translate(regs.rdi));
			break;
		case SYS_readlink:
			ret = syscall(SYS_readlink, mmu.translate(regs.rdi),
			              mmu.translate(regs.rsi), regs.rdx);
			break;
		case SYS_mprotect:
			ret = 0; // TODO
			break;
		case SYS_fstat:
			ret = syscall(SYS_fstat, regs.rdi, mmu.translate(regs.rsi));
			break;
		default:
			dump_regs();
			die("Unknown syscall: %lld\n", regs.rax);
	}

	dbgprintf("syscall %lld return %lX\n", regs.rax, ret);
	regs.rax = ret;
	ioctl_chk(vcpu.fd, KVM_SET_REGS, &regs);
}