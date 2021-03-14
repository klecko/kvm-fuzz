#ifndef _ARGS_H
#define _ARGS_H

#include <string>
#include <vector>


class Args {
public:
	int jobs;
	size_t memory;
	std::string kernel_path;
	std::string input_dir;
	std::string output_dir;
	std::string binary_path;
	std::vector<std::string> binary_argv;

	bool parse(int argc, char** argv);

private:

};

#endif