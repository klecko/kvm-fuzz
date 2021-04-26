#include "process.h"

static constexpr char g_cwd[] = "/home/l33t";
static constexpr size_t g_cwd_size =  sizeof(g_cwd) + 1;

int Process::do_sys_getcwd(UserPtr<char*> buf, size_t size) {
	if (size < g_cwd_size)
		return -ERANGE;

	// printf("asdf %lu %lu\n", size, cwd_size);

	if (!copy_to_user(buf, g_cwd, g_cwd_size))
		return -EFAULT;
	return g_cwd_size;
}

int Process::do_sys_chdir(UserPtr<const char*> path_ptr) {
	string path;
	if (!copy_string_from_user(path_ptr, path))
		return -EFAULT;

	// TODO: string comparison operator with char*
	ASSERT(path == string(g_cwd), "chdir to %s", path.c_str());
	return 0;
}