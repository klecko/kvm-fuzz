#include <fstream>
#include "tracing.h"
#include "vm.h"

using namespace std;

Tracing::Tracing(Vm& vm, Type type, Unit unit)
	: m_vm(vm)
	, m_type(type)
	, m_type_addr(0)
	, m_unit(unit)
	, m_measure({})
	, m_next_trace_id(0)
{}

Tracing::Tracing(Vm& vm, const Tracing& other)
	: m_vm(vm)
	, m_type(other.m_type)
	, m_type_addr(other.m_type_addr)
	, m_unit(other.m_unit)
	, m_measure(other.m_measure)
	, m_next_trace_id(other.m_next_trace_id)
{}

void Tracing::reset(const Tracing& other) {
	m_type = other.m_type;
	m_type_addr = other.m_type_addr;
	m_unit = other.m_unit;
	m_measure = other.m_measure;
}

void Tracing::set_type(Type type) {
	ASSERT(m_type_addr, "kernel didn't submit tracing type addr");
	m_type = type;
	m_vm.mmu().write(m_type_addr, m_type);
}

void Tracing::set_type_addr(vaddr_t type_addr) {
	m_type_addr = type_addr;
	m_vm.mmu().write(m_type_addr, m_type);
}

void Tracing::set_unit(Unit unit) {
	m_unit = unit;
}

Tracing::Type Tracing::type() const {
	return m_type;
}

size_t Tracing::trace() {
	size_t current_measure = get_tracing_measure();
	if (!m_measure.name.empty()) {
		size_t measure = current_measure - m_measure.start;
		ASSERT(measure != 0, "measure traced by syscall is 0, did you forget to "
		                     "compile with -Dinstruction-count=all ?");
		m_trace.push_back({m_measure.name, measure});
	}
	m_measure = {};
	return current_measure;
}

void Tracing::trace_and_prepare(string name) {
	size_t current_measure = trace();
	m_measure = Measure{
		.name = name,
		.start = current_measure,
	};
}

void Tracing::prepare(string name) {
	// Special case for exit_group, because it's the last syscall and therefore
	// there won't be a call to trace().
	if (name == "exit_group") {
		m_trace.push_back({name, 0});
		return;
	}

	m_measure = Measure{
		.name = name,
		.start = get_tracing_measure(),
	};
}

size_t Tracing::get_tracing_measure() {
	switch (m_unit) {
		case Unit::Instructions:
			return m_vm.read_msr(MSR_FIXED_CTR0);
		case Unit::Cycles:
			return m_vm.read_msr(MSR_FIXED_CTR1);
		default:
			ASSERT(false, "unknown Unit: %d\n", m_unit);
	};
}

void Tracing::dump_trace(size_t id) {
	if (m_type == Type::None)
		return;

	size_t trace_id = m_next_trace_id++;
	string filename = "traces/" + to_string(id) + "_" + to_string(trace_id);
	ofstream out(filename);
	for (pair<string, size_t> element : m_trace) {
		out << element.first << " " << to_string(element.second) << endl;
	}
	m_trace.clear();
}