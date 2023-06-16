#include "files.h"
#include "common.h"
#include "utils.h"

using namespace std;

size_t FileRefsByPath::size() const {
	return m_files.size();
}

bool FileRefsByPath::exists(const string& path) const {
	return m_files.count(path);
}

FileRef FileRefsByPath::file_content(const string& path) const {
	ASSERT(exists(path), "attempt to get not found file %s", path.c_str());
	return m_files.at(path).data;
}

GuestFileEntry FileRefsByPath::entry_at_pos(size_t n) {
	ASSERT(n < size(), "oob n: %lu/%lu", n, size());
	auto it = m_files.begin();
	advance(it, n);
	return GuestFileEntry{.path = it->first, .file = it->second};
}

GuestFile FileRefsByPath::set_file(const string& path, FileRef content) {
	// If file didn't exist before, guest addresses will be set to 0
	GuestFile& file = m_files[path];
	file.data = content;
	return file;
}

GuestFile SharedFiles::set_file(const std::string& path, std::string content) {
	// Content has been copied (or moved, if it was a rvalue). Move it to our
	// file contents and set a reference to it.
	string& content_ref = m_file_contents[path];
	content_ref = move(content);
	return FileRefsByPath::set_file(path, FileRef::from_string(content_ref));
}

GuestFile SharedFiles::set_file(const std::string& path) {
	return set_file(path, utils::read_file(path));
}

