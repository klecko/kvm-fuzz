#ifndef _ARGS_H
#define _ARGS_H

#include <string>
#include <vector>

struct Args {
	int jobs;
	size_t memory;
	std::string kernel_path;
	std::string input_dir;
	std::string output_dir;
	std::vector<std::string> memory_files;
	std::string binary_path;
	std::vector<std::string> binary_argv;
	std::string basic_blocks_path;
	bool single_run;
	std::string single_run_input_path;
	bool minimize_corpus;
	bool minimize_crashes;

	bool parse(int argc, char** argv);
};

#endif