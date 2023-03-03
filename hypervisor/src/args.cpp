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
#include <getopt.h>
#include <string.h>
#include "args.h"
#include "utils.h"

using namespace std;

bool parse_memory(const string& s, size_t& result) {
	size_t i = 0;
	result = stoi(s, &i);
	switch (s[i]) {
		case 'G':
			result *= 1024;
		case 'M':
			result *= 1024;
		case 'K':
			result *= 1024;
		case 0:
			break;
		default:
			return false;
	}
	return true;
}


#ifdef DEBUG
const uint Args::DEFAULT_NUM_THREADS = 1;
#else
const uint Args::DEFAULT_NUM_THREADS = std::thread::hardware_concurrency();
#endif

void print_usage() {
	printf(
	"kvm-fuzz: fuzz x86_64 closed-source applications with hardware acceleration\n\n"

	"Usage:\n"
	"  kvm-fuzz [ options ] -- /path/to/fuzzed_binary [ args ]\n\n"

	"Available options:\n"
	"      --minimize-corpus     Set corpus minimization mode\n"
	"      --minimize-crashes    Set crashes minimization mode\n"
	"  -j, --jobs n              Number of threads to use (default: %u)\n"
	"  -m, --memory arg          Virtual machine memory limit (default: 8M)\n"
	"  -t, --timeout ms          Timeout for each in run in milliseconds, or 0 for no\n"
	"                            timeout (default: 2)\n"
	"  -k, --kernel path         Kernel path (default: ./zig-out/bin/kernel)\n"
	"  -i, --input dir           Input folder (initial corpus) (default: ./in)\n"
	"  -o, --output dir          Output folder (corpus, crashes, etc) (default: ./out)\n"
	"  -f, --file path           Memory loaded files for the target. Set once for\n"
	"                            each file: -f file1 -f file2\n"
	"  -s, --single-run [=path]  Perform a single run, optionally specifying an\n"
	"                            input file\n"
	"  -T, --tracing type        Enable syscall tracing. Type can be kernel or user\n"
	"      --tracing-unit unit   Tracing unit. It can be instructions or cycles (default cycles)\n"
	"  -h, --help                Print usage\n"
	, Args::DEFAULT_NUM_THREADS);
}

enum LongOptions {
	MinimizeCorpus = 0x100,
	MinimizeCrashes,
	TracingUnit,
};

bool Args::parse(int argc, char** argv) {
	option long_options[] = {
		{"minimize-corpus", no_argument, nullptr, LongOptions::MinimizeCorpus},
		{"minimize-crashes", no_argument, nullptr, LongOptions::MinimizeCrashes},
		{"jobs", required_argument, nullptr, 'j'},
		{"memory", required_argument, nullptr, 'm'},
		{"timeout", required_argument, nullptr, 't'},
		{"kernel", required_argument, nullptr, 'k'},
		{"input", required_argument, nullptr, 'i'},
		{"output", required_argument, nullptr, 'o'},
		{"file", required_argument, nullptr, 'f'},
		{"single-run", optional_argument, nullptr, 's'},
		{"tracing", required_argument, nullptr, 'T'},
		{"tracing-unit", required_argument, nullptr, LongOptions::TracingUnit},
		{"help", no_argument, nullptr, 'h'},
		{0, 0, 0, 0},
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "j:m:t:k:i:o:f:s::T:h", long_options, nullptr)) > 0) {
		switch (opt) {
			case LongOptions::MinimizeCorpus:
				minimize_corpus = true;
				break;
			case LongOptions::MinimizeCrashes:
				minimize_crashes = true;
				break;
			case 'j':
				if ((sscanf(optarg, "%u", &jobs) < 1) || (jobs == 0)) {
					printf("Option -j, --jobs must be followed by a number.\n\n");
					print_usage();
					return false;
				}
				break;
			case 'm':
				if (!parse_memory(optarg, memory)) {
					printf("Option -m, --memory must be followed by a number, "
					       "optionally followed by K, M, or G.\n\n");
					print_usage();
					return false;
				}
				break;
			case 't':
				if (sscanf(optarg, "%lu", &timeout) < 1) {
					printf("Option -t, --timeout must be followed by a number.\n\n");
					print_usage();
					return false;
				}
				break;
			case 'k':
				kernel_path = optarg;
				break;
			case 'i':
				input_dir = optarg;
				break;
			case 'o':
				output_dir = optarg;
				break;
			case 'f':
				memory_files.push_back(optarg);
				break;
			case 's':
				single_run = true;
				if (optarg)
					single_run_input_path = optarg;
				break;
			case 'T':
				if (!strcmp(optarg, "kernel"))
					tracing_type = Tracing::Type::Kernel;
				else if (!strcmp(optarg, "user"))
					tracing_type = Tracing::Type::User;
				else {
					printf("Option -T, --tracing must be followed by 'kernel' or 'user'\n\n");
					print_usage();
					return false;
				}
				break;
			case LongOptions::TracingUnit:
				if (!strcmp(optarg, "cycles"))
					tracing_unit = Tracing::Unit::Cycles;
				else if (!strcmp(optarg, "instructions"))
					tracing_unit = Tracing::Unit::Instructions;
				else {
					printf("Option --tracing-unit must be followed by 'instructions' or 'cycles'\n\n");
					print_usage();
					return false;
				}
				break;
			case 'h':
			case '?':
			default:
				print_usage();
				return false;
		}
	}

	// Positional arguments: binary_path and binary_argv
	int i = optind;
	if (i == argc) {
		printf("Missing fuzzed binary path\n\n");
		print_usage();
		return false;
	}

	binary_path = argv[i];
	for (; i < argc; i++) {
		binary_argv.push_back(argv[i]);
	}

	// Check mode
	if (minimize_corpus && minimize_crashes) {
		printf("You can't specify both --minimize-corpus and --minimize-crashes.\n\n");
		print_usage();
		return false;
	}

#ifdef ENABLE_COVERAGE_INTEL_PT
	if (tracing_type == Tracing::Type::User) {
		printf("Tracing user is not available with Intel PT.\n");
		return false;
	}
#endif

#ifndef ENABLE_COVERAGE
	if (tracing_type != Tracing::Type::None) {
		printf("Tracing enabled but coverage is disabled.\n");
		return false;
	}
#endif

	if (tracing_type != Tracing::Type::None && timeout != 0) {
		printf("Tracing and timeout are both enabled, you may want to disable timeout to avoid incomplete traces.\n\n");
	}

	// Convert timeout to microsecs, or set it to maximum value if it was 0
	if (timeout == 0)
		timeout = numeric_limits<size_t>::max();
	else
		timeout *= 1000;

	return true;
}