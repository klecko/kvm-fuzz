#include <vector>
#include "elf_parser.h"
#include "files.h"

class Elfs {
public:
	Elfs();

	Elfs(const std::string& binary_path, const std::string& kernel_path);

	~Elfs();

	void init(const std::string& binary_path, const std::string& kernel_path);

	ElfParser& elf();
	ElfParser& kernel();
	ElfParser* interpreter();
	std::vector<const ElfParser*> all_elfs() const;
	void add_library(const std::string& filename, FileRef content);
	void set_library_load_addr(const std::string& filename, vaddr_t load_addr);

private:
	ElfParser  m_elf;
	ElfParser  m_kernel;
	ElfParser* m_interpreter;

	// These don't own memory
	std::unordered_map<std::string, ElfParser> m_libraries;
};