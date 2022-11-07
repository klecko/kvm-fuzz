#define CATCH_CONFIG_FAST_COMPILE
#define CATCH_CONFIG_NO_POSIX_SIGNALS
#include "vm.h"
#include "catch.hpp"

extern Stats stats;

inline vaddr_t addr(Vm& vm, vaddr_t rel) {
	return vm.elf().entry()+rel;
}