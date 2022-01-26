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
	GuestPtrs guest;
};


class FileRefsByPath {
public:
	size_t size() const;

	bool exists(const std::string& path) const;

	FileRef file_content(const std::string& path) const;
	FileRef file_content(size_t n) const;
	std::pair<std::string, GuestFile> entry_at_pos(size_t n) const;

	GuestFile set_file(const std::string& path, FileRef content);

	void set_guest_ptrs_at_pos(size_t n, GuestPtrs guest_ptrs);

private:
	// Files contents indexed by filename. Kernel will synchronize with this
	// on startup
	// Files indexed by filename. We are not owner of the contents, which may
	// live in the Corpus or in the SharedFiles
	std::unordered_map<std::string, GuestFile> m_files;

	GuestFile& file_at_pos(size_t n);
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