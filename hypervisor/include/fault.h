#ifndef _FAULT_H
#define _FAULT_H

#include <iostream>
#include <string>
#include <sstream>
#include "kvm_aux.h"
#include "common.h"

// Keep this the same as in the kernel
struct FaultInfo {
	enum Type {
		Read,
		Write,
		Exec,
		OutOfBoundsRead,
		OutOfBoundsWrite,
		OutOfBoundsExec,
		AssertionFailed,
		DivByZero,
		GeneralProtectionFault,
		StackSegmentFault,
	};

	Type type;
	uint64_t fault_addr;
	bool kernel;
	kvm_regs regs;

	bool operator==(const FaultInfo& other) const {
		// Regarding registers, we are considering two faults identical if they
		// happened at the same RIP.
		return type == other.type &&
		       fault_addr == other.fault_addr &&
		       kernel == other.kernel &&
		       regs.rip == other.regs.rip;
	}

	const char* type_str() const {
		switch (type){
			case Type::Read:
				return "Read";
			case Type::Write:
				return "Write";
			case Type::Exec:
				return "Exec";
			case Type::OutOfBoundsRead:
				return "OutOfBoundsRead";
			case Type::OutOfBoundsWrite:
				return "OutOfBoundsWrite";
			case Type::OutOfBoundsExec:
				return "OutOfBoundsExec";
			case Type::AssertionFailed:
				return "AssertionFailed";
			case Type::DivByZero:
				return "DivByZero";
			case Type::GeneralProtectionFault:
				return "GeneralProtectionFault";
			case Type::StackSegmentFault:
				return "StackSegmentFault";
			default:
				return "Unimplemented?";
		}
	}

	std::string filename() const {
		std::ostringstream ret;
		if (kernel)
			ret << "Kernel_";
		ret << type_str() << "_0x" << std::hex << regs.rip << "_0x" << fault_addr;
		return ret.str();
	}
};

inline std::ostream& operator<<(std::ostream& os, const FaultInfo& fault) {
	os << std::hex << "[";
	if (fault.kernel)
		os << "KERNEL ";
	os << "CRASH: " << fault.type_str() << "] RIP: 0x" << fault.regs.rip
	   << ", address: 0x" << fault.fault_addr << std::endl;
	os << fault.regs;
	os << std::dec;
	return os;
}

namespace std {
	template <>
	struct hash<FaultInfo> {
		std::size_t operator()(const FaultInfo& fault) const {
			return
				fault.type ^
				hash<bool>()(fault.kernel) ^
				hash<size_t>()(fault.fault_addr) ^
				hash<size_t>()(fault.regs.rip);
		}
	};
}
#endif