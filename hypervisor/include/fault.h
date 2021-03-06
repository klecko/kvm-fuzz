#ifndef _FAULT_H
#define _FAULT_H

#include <iostream>
#include "common.h"

struct FaultInfo {
	enum Type {
		Read,
		Write,
		Exec,
		OutOfBoundsRead,
		OutOfBoundsWrite,
		OutOfBoundsExec,
	};

	Type type;
	uint64_t rip;
	uint64_t fault_addr;

	bool operator==(const FaultInfo& other) const {
		return type == other.type &&
		       rip == other.rip &&
			   fault_addr == other.fault_addr;
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
			default:
				return "Unimplemented?";
		}
	}
};

inline std::ostream& operator<<(std::ostream& os, const FaultInfo& fault) {
	os << std::hex;
	os << "[CRASH: " << fault.type_str() << "] RIP: 0x" << fault.rip
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