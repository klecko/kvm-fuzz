#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <sys/stat.h>
#include <openssl/md5.h>
#include "utils.h"
#include "common.h"

using namespace std;

void create_folder(const string& name){
	// If folder doesn't exist, create it. If it exists, check it is an
	// actual folder
	const char* name_s = name.c_str();
	struct stat st;
	if (stat(name_s, &st) == -1){
		ERROR_ON(mkdir(name_s, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH) == -1,
		         "Creating dir %s", name_s);
	} else ASSERT(st.st_mode & S_IFDIR, "%s exists but isn't a folder", name_s);
}

string read_file(const string& filepath) {
	ifstream ifs(filepath);
	ERROR_ON(!ifs.good(), "Error opening file %s for reading", filepath.c_str());
	string content((istreambuf_iterator<char>(ifs)),
	               (istreambuf_iterator<char>()));
	ERROR_ON(!ifs.good(), "Error reading file %s", filepath.c_str());
	ifs.close();
	return content;
}

void write_file(const string& filepath, const string& content) {
	ofstream ofs(filepath);
	ERROR_ON(!ofs.good(), "Error opening file %s for writing", filepath.c_str());
	ofs << content;
	ERROR_ON(!ofs.good(), "Error writing to file %s", filepath.c_str());
	ofs.close();
}

string md5(const string& s) {
	return md5((const uint8_t*)s.c_str(), s.size());
}

string md5(const uint8_t* buf, size_t length) {
	// Perform hash
	uint8_t hash[MD5_DIGEST_LENGTH];
	MD5(buf, length, hash);

	// Get hex representation
	ostringstream ss;
	ss << hex;
	for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++)
		ss << setw(2) << setfill('0') << (int)hash[i];
	return ss.str();
}

string md5_file(const string& filepath) {
	return md5(read_file(filepath));
}

string to_hex(size_t num) {
	ostringstream ss;
	ss << hex << num;
	return ss.str();
}