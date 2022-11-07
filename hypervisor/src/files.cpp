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

FileRef FileRefsByPath::file_content(size_t n) const {
	return entry_at_pos(n).second.data;
}

pair<string, GuestFile> FileRefsByPath::entry_at_pos(size_t n) const {
	ASSERT(n < size(), "oob n: %lu/%lu", n, size());
	auto it = m_files.begin();
	advance(it, n);
	return *it;
}

GuestFile& FileRefsByPath::file_at_pos(size_t n) {
	ASSERT(n < size(), "oob n: %lu/%lu", n, size());
	auto it = m_files.begin();
	advance(it, n);
	return it->second;
}

GuestFile FileRefsByPath::set_file(const string& path, FileRef content) {
	// If file didn't exist before, guest addresses will be set to 0
	// i'm not completely sure of this so let's add some assertions :')
	bool existed = m_files.count(path);
	GuestFile& file = m_files[path];
	file.data = content;
	if (!existed) {
		ASSERT(file.guest.data_addr == 0, "");
		ASSERT(file.guest.length_addr == 0, "");
	}
	return file;
}

void FileRefsByPath::set_guest_ptrs_at_pos(size_t n, GuestPtrs guest_ptrs) {
	GuestFile& file = file_at_pos(n);
	file.guest = guest_ptrs;
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

