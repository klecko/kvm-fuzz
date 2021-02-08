#include <iostream>
#include "vm.h"

using namespace std;

int main(int argc, char** argv) {
	init_kvm();
	Vm vm(1024 * 1024, "../target_ez", {"../target"});

	cout << "[BEFORE RUNNING]" << endl;
	vm.dump_regs();
	vm.dump_memory();

	vm.run();

	cout << endl << "[AFTER RUNNING]" << endl;
	vm.dump_regs();
	vm.dump_memory();

	return 0;
}