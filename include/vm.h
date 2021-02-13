#ifndef _VM_H
#define _VM_H

#include <iostream>
#include <vector>
#include <unordered_map>
#include "mmu.h"
#include "elf_parser.hpp"
#include "common.h"
#include "kvm_aux.h"

void init_kvm();

class Vm {
public:
	Vm(vsize_t mem_size, const std::string& filepath,
	   const std::vector<std::string>& argv);
	Vm(const Vm& other);

	void reset(const Vm& other);
	psize_t memsize() const;
	void run();
	void run_until(vaddr_t pc);
	void dump_regs();
	void dump_memory() const;
	void dump_memory(psize_t len) const;
	void set_breakpoint(vaddr_t addr);
	void remove_breakpoint(vaddr_t addr);

private:
	int vm_fd;
	struct {
		int fd;
		struct kvm_run* run;
	} vcpu;
	Elf_parser elf;
	Mmu mmu;
	bool running;
	std::unordered_map<vaddr_t, uint8_t> breakpoints_original_bytes;

	void setup_long_mode();
	void load_elf(const std::vector<std::string>& argv);
	void handle_syscall();
	uint64_t do_sys_arch_prctl(const kvm_regs& regs);
	void vm_err(const std::string& err);
};

#endif