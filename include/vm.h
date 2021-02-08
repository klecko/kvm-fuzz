#ifndef _VM_H
#define _VM_H

#include <iostream>
#include <vector>
#include "mmu.h"
#include "elf_parser.hpp"
#include "common.h"

void init_kvm();

class Vm {
public:
	Vm(vsize_t mem_size, const std::string& filepath,
	   const std::vector<std::string>& argv);

	psize_t memsize() const;
	void run();
	void dump_regs();
	void dump_memory() const;
	void dump_memory(psize_t len) const;

private:
	int vm_fd;
	struct {
		int fd;
		struct kvm_run* run;
	} vcpu;
	Elf_parser elf;
	Mmu mmu;
	bool running;

	void setup_long_mode();
	void load_elf(const std::vector<std::string>& argv);
	void handle_syscall();
};

#endif