#ifndef _FAULT_H
#define _FAULT_H

#include <iostream>
#include <string>
#include <sstream>
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
	};

	Type type;
	uint64_t rip;
	uint64_t fault_addr;
	bool kernel;

	bool operator==(const FaultInfo& other) const {
		return type == other.type &&
		       rip == other.rip &&
		       fault_addr == other.fault_addr &&
		       kernel == other.kernel;
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
			default:
				return "Unimplemented?";
		}
	}

	std::string filename() const {
		std::ostringstream ret;
		if (kernel)
			ret << "Kernel_";
		ret << type_str() << "_0x" << std::hex << rip << "_0x" << fault_addr;
		return ret.str();
	}
};

inline std::ostream& operator<<(std::ostream& os, const FaultInfo& fault) {
	os << std::hex << "[";
	if (fault.kernel)
		os << "KERNEL ";
	os << "CRASH: " << fault.type_str() << "] RIP: 0x" << fault.rip
	   << ", address: 0x" << fault.fault_addr;
	os << std::dec;
	return os;
}

namespace std {
	template <>
	struct hash<FaultInfo> {
		std::size_t operator()(const FaultInfo& fault) const {
			return fault.type ^
			       hash<uint64_t>()(fault.rip) ^
				   hash<uint64_t>()(fault.fault_addr);
		}
	};
}
#endif