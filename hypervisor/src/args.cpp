/* Argument parsing. I decided to use cxxopts, a lightweight parser:
 * 	https://github.com/jarro2783/cxxopts/
 *
 * I also tried using boost, but I found cxxopts' interface much more intuitive,
 * and its output was also much better. The only problem is the high compilation
 * time.
 */

#include <thread>
#include <fstream>
#include <sstream>
#include "args.h"
#include "cxxopts.hpp"
#include "utils.h"

using namespace std;

#ifdef DEBUG
#define DEFAULT_NUM_THREADS 1
#else
#define DEFAULT_NUM_THREADS thread::hardware_concurrency()
#endif

size_t parse_memory(const string& s) {
	size_t i = 0;
	size_t value = stoi(s, &i);
	switch (s[i]) {
		case 'G':
			value *= 1024;
		case 'M':
			value *= 1024;
		case 'K':
			value *= 1024;
		case 0:
			break;
		default:
			throw cxxopts::OptionParseException("invalid memory: " + s);
	}
	return value;
}

bool Args::parse(int argc, char** argv) {
	// Fuck 80 chars limit.
	try {
		cxxopts::Options cmd("kvm-fuzz", "kvm-fuzz: fuzz x86_64 closed-source applications with hardware acceleration\n");
		cmd.add_options("Available")
			("minimize-corpus", "Set corpus minimization mode", cxxopts::value<bool>(minimize_corpus))
			("minimize-crashes", "Set crashes minimization mode", cxxopts::value<bool>(minimize_crashes))
			("j,jobs", "Number of threads to use", cxxopts::value<int>(jobs)->default_value(to_string(DEFAULT_NUM_THREADS)), "n")
			("m,memory", "Virtual machine memory limit", cxxopts::value<string>()->default_value("8M"))
			("t,timeout", "Timeout for each in run in milliseconds, or 0 for no timeout", cxxopts::value<size_t>(timeout)->default_value("2"), "ms")
			("k,kernel", "Kernel path", cxxopts::value<string>(kernel_path)->default_value("./kernel/kernel"), "path")
			("i,input", "Input folder (initial corpus)", cxxopts::value<string>(input_dir)->default_value("./in"), "dir")
			("o,output", "Output folder (corpus, crashes, etc)", cxxopts::value<string>(output_dir)->default_value("./out"), "dir")
			("f,file", "Memory loaded files for the target. Set once for each file, or as a list: -f file1,file2", cxxopts::value<vector<string>>(memory_files), "path")
			("b,basic-blocks", "Path to file containing a list of basic blocks for code coverage. Default value is ./basic_blocks/<BinaryMD5Hash>.txt", cxxopts::value<string>(basic_blocks_path), "path")
			("s,single-run", "Perform a single run, optionally specifying an input file", cxxopts::value<string>(single_run_input_path)->implicit_value("none"), "path")
			("binary", "File to run", cxxopts::value<string>(binary_path))
			("args", "Args passed to binary", cxxopts::value<vector<string>>(binary_argv))
			("h,help", "Print usage")
		;

		// Set positional arguments
		cmd.parse_positional({"binary", "args"});

		// Set custom usage help and width
		cmd.custom_help("[ options ]")
		   .positional_help("-- /path/to/fuzzed_binary [ args ]")
		   .set_width(80);

		auto options = cmd.parse(argc, argv);

		// Display help
		if (options.count("help") || !options.count("binary") ||
		   (minimize_corpus && minimize_crashes))
		{
			cout << cmd.help() << endl;
			return false;
		}

		// Parse special arguments
		memory = parse_memory(options["memory"].as<string>());

		// Add binary path to argv
		binary_argv.insert(binary_argv.begin(), binary_path);

		// Set default basic block file
		if (basic_blocks_path.empty()) {
			create_folder("./basic_blocks");
			string md5 = md5_file(binary_path);
			basic_blocks_path = "./basic_blocks/" + md5 + ".txt";
		}

		if (options.count("single-run")) {
			// Option was specified. If there is no input file given, just
			// clear that argument
			single_run = true;
			if (single_run_input_path == "none")
				single_run_input_path.clear();
		} else {
			single_run = false;
		}

		// Convert timeout to microsecs, or set it to maximum value if it was 0
		if (timeout == 0)
			timeout = numeric_limits<size_t>::max();
		else
			timeout *= 1000;

	} catch (cxxopts::OptionException& e) {
		cout << "error: " << e.what() << endl;
		return false;
	}

	return true;
}