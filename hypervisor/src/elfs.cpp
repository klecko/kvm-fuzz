#include <iostream>
#include "elfs.h"

using namespace std;

Elfs::Elfs()
	: m_interpreter(nullptr)
{}

Elfs::Elfs(const string& binary_path, const string& kernel_path) : Elfs() {
	init(binary_path, kernel_path);
}

Elfs::~Elfs() {
	if (m_interpreter)
		delete m_interpreter;
}

void Elfs::init(const string& binary_path, const string& kernel_path) {
	if (m_interpreter) {
		delete m_interpreter;
		m_interpreter = nullptr;
		m_libraries.clear();
	}

	m_elf = ElfParser(binary_path);
	m_kernel = ElfParser(kernel_path);
	if (!m_elf.interpreter().empty()) {
		m_interpreter = new ElfParser(m_elf.interpreter());
		ASSERT(m_interpreter->is_pie(), "interpreter not PIE");
	}
	ASSERT(!m_kernel.is_pie(), "Kernel is PIE");
	ASSERT(m_kernel.interpreter().empty(), "Kernel is dynamically linked");
}

ElfParser& Elfs::elf() {
	return m_elf;
}

ElfParser& Elfs::kernel() {
	return m_kernel;
}

ElfParser* Elfs::interpreter() {
	return m_interpreter;
}

std::vector<const ElfParser*> Elfs::all_elfs() const {
	std::vector<const ElfParser*> elfs = {&m_elf, &m_kernel};
	if (m_interpreter)
		elfs.push_back(m_interpreter);
	for (const auto& library : m_libraries) {
		elfs.push_back(&library.second);
	}
	return elfs;
}

std::vector<const ElfParser*> Elfs::target_elfs() const {
	// Just user elf and libraries
	std::vector<const ElfParser*> elfs = {&m_elf};
	for (const auto& library : m_libraries) {
		elfs.push_back(&library.second);
	}
	return elfs;
}

void Elfs::add_library(const string& filename, FileRef content) {
	ASSERT(!m_libraries.count(filename), "library added twice %s", filename.c_str());
	ElfParser library(filename, (const uint8_t*)content.ptr, content.length);
	m_libraries[filename] = move(library);
}

void Elfs::set_library_load_addr(const string& filename, vaddr_t load_addr) {
	//ASSERT(m_libraries.count(filename), "library not found %s", filename.c_str());
	if (!m_libraries.count(filename)) {
		printf("Warning: guest loaded not available library %s at 0x%lx. "
		       "It won't be possible to get symbols or stacktraces from it.\n",
			   filename.c_str(), load_addr);
		return;
	}

	ElfParser& library = m_libraries.at(filename);
	if (!library.load_addr()) {
		library.set_load_addr(load_addr);
		printf("Guest loaded library %s at 0x%lx\n", filename.c_str(), load_addr);
	}
}
