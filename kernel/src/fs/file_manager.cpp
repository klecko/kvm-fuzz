#include "map"
#include "vector"
#include "fs/file_manager.h"

namespace FileManager {

map<string, struct iovec> g_file_contents;

void init(size_t num_files) {
	// For each file, get its filename and its length and allocate a buffer
	// for the file content. Submit the address of the buffer and the address of
	// the length to the hypervisor, which will write file contents into the
	// buffer and real file length into the length.
	void* buf;
	size_t size;
	char filename[PATH_MAX];
	for (size_t i = 0; i < num_files; i++) {
		hc_get_file_name(i, filename);
		size = hc_get_file_len(i);
		buf = kmalloc(size);
		struct iovec& iov = g_file_contents[string(filename)];
		iov.iov_base = buf;
		iov.iov_len  = size;
		hc_submit_file_pointers(i, iov.iov_base, &iov.iov_len);
	}

	dbgprintf("Files: %d\n", g_file_contents.size());
	for (auto v : g_file_contents) {
		dbgprintf("\t%s, length %lu\n", v.f.c_str(), v.s.iov_len);
	}
}

bool exists(const string& pathname) {
	return g_file_contents.count(pathname);
}

struct iovec file_content(const string& pathname) {
	ASSERT(exists(pathname), "attempt to get contents of not existing file: %s",
	       pathname.c_str());
	return g_file_contents[pathname];
}

FileDescription* open(const string& pathname, int flags) {
	// The idea is that checks are performed in syscalls, and here we just
	// panic if something goes wrong.
	struct iovec content = file_content(pathname);
	FileDescription* description = new FileDescription(
		flags,
		(const char*)content.iov_base,
		content.iov_len
	);
	return description;
}

FileDescriptionSocket* open_socket(SocketType type) {
	struct iovec content = file_content("input");
	return new FileDescriptionSocket(
		(const char*)content.iov_base,
		content.iov_len,
		type
	);
}

FileDescription* open(SpecialFile file) {
	switch (file) {
		case Stdin:
			return new FileDescriptionStdin();
		case Stdout:
			return new FileDescriptionStdout();
		case Stderr:
			return new FileDescriptionStderr();
	}
	UNREACHABLE;
	return nullptr;
}

int stat(const string& pathname, UserPtr<struct stat*> stat_ptr) {
	struct iovec iov = file_content(pathname);
	return FileDescription::stat_regular(
		stat_ptr,
		iov.iov_len,
		(inode_t)iov.iov_base
	);
}

}
