#include <fstream>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <vector>
#include "utils.h"
#include "common.h"

using namespace std;

namespace utils {

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

string exec_cmd(const string& cmd) {
	char buffer[128];
	string result = "";
	FILE* pipe = popen(cmd.c_str(), "r");
	ERROR_ON(!pipe, "Error running cmd '%s'", cmd.c_str());
	while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
		result += buffer;
	}
	pclose(pipe);
	return result;
}

vector<string> split_string(const string& s, const string& delimiter) {
	vector<string> result;
	size_t pos1 = 0, pos2;
	while ((pos2 = s.find(delimiter, pos1)) != string::npos) {
		result.push_back(s.substr(pos1, pos2-pos1));
		pos1 = pos2 + 1;
	}
	return result;
}

string secs_to_str(size_t seconds) {
	size_t hours = seconds / 3600;
	size_t minutes = (seconds / 60) % 60;
	seconds = seconds % 60;
	string ret;
	if (hours)
		ret += to_string(hours) + "h ";
	if (minutes || hours)
		ret += to_string(minutes) + "m ";
	ret += to_string(seconds) + "s";
	return ret;
}

};