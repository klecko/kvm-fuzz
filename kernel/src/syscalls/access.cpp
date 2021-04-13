#include "process.h"
#include "file_manager.h"

int Process::do_sys_access(UserPtr<const char*> pathname_ptr, int mode) {
	string pathname;
	if (!copy_string_from_user(pathname_ptr, pathname))
		return -EFAULT;
	if (!FileManager::exists(pathname))
		return -EACCES;
	if ((mode & W_OK) || (mode & X_OK)) {
		printf_once("access %s, mode %d, denying\n", pathname.c_str(), mode);
		return -EACCES;
	}
	// It's asking for R_OK or F_OK
	return 0;
}