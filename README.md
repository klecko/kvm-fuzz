# kvm-fuzz
The goal is to emulate and fuzz x86_64 binaries using KVM. The original idea was simply running userspace code inside the virtual machine, generating a VM exit when it called a syscall, which was then satisfied by the hypervisor. However, performance was bad when there were a significant amount of syscalls because VM exits are very expensive. In order to solve this, syscalls are now handled in the kernel inside the VM, so the only VM exit is at the end of each run.

Code coverage is achieved either using breakpoint-based coverage (something like [mesos](https://github.com/gamozolabs/mesos) but much smaller), or using Intel Processor Trace. Intel PT is implemented using KVM-PT, a modified linux kernel used by [kAFL](https://github.com/IntelLabs/kAFL) which allows tracing virtual CPUs (you can see the paper [here](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf)). Packet decoding is done using [libxdc](https://github.com/klecko/libxdc), also released by Sergej ([@ms_s3c](https://twitter.com/ms_s3c)) and Cornelius ([@is_eqv](https://twitter.com/is_eqv)).

```
kvm-fuzz: fuzz x86_64 closed-source applications with hardware acceleration

Usage:
  kvm-fuzz [ options ] -- /path/to/fuzzed_binary [ args ]

Available options:
  -j, --jobs arg           Number of threads to use (default: 8)
  -m, --memory arg         Virtual machine memory limit (default: 8M)
  -k, --kernel path        Kernel path (default: ./kernel/kernel)
  -i, --input dir          Input folder (initial corpus) (default: ./corpus)
  -o, --output dir         Output folder (crashes) (default: ./crashes)
  -f, --file path          Memory loaded files for the target. Set once for 
                           each file, or as a list: -f file1,file2
  -b, --basic-blocks path  Path to file containing a list of basic blocks for 
                           code coverage. Default value is 
                           basic_blocks_<BinaryMD5Hash>.txt
  -s, --single-input path  Path to single input file. A single run will be 
                           performed with this input.
  -h, --help               Print usage
```
