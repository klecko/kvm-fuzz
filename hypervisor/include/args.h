#ifndef _ARGS_H
#define _ARGS_H

#include <string>
#include <vector>

struct Args {
	static const uint DEFAULT_NUM_THREADS;

	uint jobs = DEFAULT_NUM_THREADS;
	size_t memory = 8*1024*1024;
	size_t timeout = 2;
	std::string kernel_path = "./zig-out/bin/kernel";
	std::string input_dir = "./in";
	std::string output_dir = "./out";
	std::vector<std::string> memory_files;
	std::string binary_path;
	std::vector<std::string> binary_argv;
	bool single_run = false;
	std::string single_run_input_path;
	bool minimize_corpus = false;
	bool minimize_crashes = false;
	bool tracing = false;

	// Args(int argc, char** argv);
	bool parse(int argc, char** argv);
	// bool parse_old(int argc, char** argv);
};

#endif