#ifndef _TRACING_H
#define _TRACING_H

#include <iostream>
#include "common.h"

class Vm;

class Tracing {
public:
	// Keep this the same as in the kernel
	enum class Type : int {
		None,
		Kernel,
		User,
	};

	enum class Unit {
		Cycles,
		Instructions,
	};

	struct Measure {
		std::string name;
		uint64_t start;
	};


	Tracing(Vm& vm, Type type = Type::None, Unit unit = Unit::Cycles);
	Tracing(Vm& vm, const Tracing& other);
	void reset(const Tracing& other);
	void set_type(Type type);
	void set_type_addr(vaddr_t type_addr);
	void set_unit(Unit unit);
	Type type() const;
	size_t trace();
	void trace_and_prepare(std::string name);
	void prepare(std::string name);
	size_t get_tracing_measure();
	void dump_trace(size_t id = 0);

private:
	Vm& m_vm;
	Type m_type;
	vaddr_t m_type_addr;
	Unit m_unit;
	Measure m_measure;
	size_t m_next_trace_id;
	std::vector<std::pair<std::string, size_t>> m_trace;
};

#endif