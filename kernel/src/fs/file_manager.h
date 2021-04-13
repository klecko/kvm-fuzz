#ifndef _FILE_MANAGER_H
#define _FILE_MANAGER_H

#include "common.h"
#include "fs/file_description.h"
#include "linux/stat.h"

namespace FileManager {

enum SpecialFile {
	Stdin,
	Stdout,
	Stderr
};

void init(size_t num_files);
bool exists(const string& pathname);
FileDescription& open(const string& pathname, int flags);
FileDescription& open(SpecialFile file);
int stat(const string& pathname, UserPtr<struct stat*> stat_ptr);

}

#endif