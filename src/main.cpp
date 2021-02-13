#include <iostream>
#include <thread>
#include "vm.h"

using namespace std;

void worker(const Vm& base) {
	Vm runner(base);
	while (true) {
		runner.run();
		runner.reset(base);
	}
}

int main(int argc, char** argv) {
	init_kvm();
	Vm vm(1024 * 1024, "../target", {"../target"});
	vm.run_until(0x401d35);
	worker(vm);
	return 0;

	cout << "[BEFORE RUNNING]" << endl;
	vm.dump_regs();
	cout << endl;
	//vm.dump_memory();

	vm.run_until(0x401d35);

	cout << endl << "[AFTER RUNNING]" << endl;
	vm.dump_regs();
	cout << endl;
	//vm.dump_memory();

	Vm vm2(vm);

	cout << "[BEFORE RUNNING2]" << endl;
	vm.dump_regs();
	cout << endl;
	//vm.dump_memory();

	vm.run();

	cout << endl << "[AFTER RUNNING2]" << endl;
	vm.dump_regs();
	cout << endl;

	cout << "Resetting..." << endl;
	vm.reset(vm2);

	cout << "[BEFORE RUNNING3]" << endl;
	vm.dump_regs();
	cout << endl;
	//vm.dump_memory();

	vm.run();

	cout << endl << "[AFTER RUNNING3]" << endl;
	vm.dump_regs();
	cout << endl;
	return 0;
}