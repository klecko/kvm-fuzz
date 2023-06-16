#ifndef _SHARED_FILES_H
#define _SHARED_FILES_H

#include <vector>
#include <unordered_map>
#include "elf_parser.h"

struct FileRef {
	const void* ptr;
	size_t length;

	static FileRef from_string(const std::string& s) {
		return {
			.ptr = s.c_str(),
			.length = s.length(),
		};
	}
};

struct GuestPtrs {
	vaddr_t data_addr;
	vaddr_t length_addr;
};

struct GuestFile {
	FileRef data;
	GuestPtrs guest_ptrs;
};

struct GuestFileEntry {
	const std::string& path;
	GuestFile& file;
};

class FileRefsByPath {
public:
	size_t size() const;

	bool exists(const std::string& path) const;

	FileRef file_content(const std::string& path) const;
	GuestFileEntry entry_at_pos(size_t n);
	GuestFile set_file(const std::string& path, FileRef content);

private:
	// Files indexed by filename. Kernel will synchronize with this on startup.
	// We are not owner of the contents, which may live in the Corpus, in the
	// SharedFiles, or somewhere else.
	std::unordered_map<std::string, GuestFile> m_files;
};

class SharedFiles : public FileRefsByPath {
public:
	// Don't let setting a file by reference.
	GuestFile set_file(const std::string& path, FileRef content) = delete;
	GuestFile set_file(const std::string& path, std::string content);
	GuestFile set_file(const std::string& path);

private:
	// Backing file contents
	std::unordered_map<std::string, std::string> m_file_contents;
};

#endif