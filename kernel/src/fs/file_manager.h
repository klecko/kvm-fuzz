#ifndef _FS_FILE_MANAGER_H
#define _FS_FILE_MANAGER_H

#include "common.h"
#include "fs/file_description.h"
#include "linux/stat.h"
#include "linux/uio.h"

namespace FileManager {

enum SpecialFile {
	Stdin,
	Stdout,
	Stderr,
};

// Initiate the file manager, getting memory-loaded files from the hypervisor
void init(size_t num_files);

// Check if a memory-loaded file exists
bool exists(const string& pathname);

// Returns the file content of an existing file given its pathname
struct iovec file_content(const string& pathname);

// Open a memory-loaded file
FileDescription* open(const string& pathname, int flags);

// Open a special file
FileDescription* open(SpecialFile file);

// Open a socket, which will read from file 'input'
FileDescriptionSocket* open_socket(SocketType type);

// Perform stat on a file. Used by syscall stat.
int stat(const string& pathname, UserPtr<struct stat*> stat_ptr);

}

#endif