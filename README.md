# kvm-fuzz
The goal is to emulate and fuzz x86_64 binaries using KVM. The original idea was simply running userspace code inside the virtual machine, generating a VM exit when it called a syscall, which was then satisfied by the hypervisor. However, performance was bad when there were a significant amount of syscalls because VM exits are very expensive. In order to solve this, syscalls are now handled in the kernel inside the VM, so the only VM exit is at the end of each run.

Code coverage is achieved either using breakpoint-based coverage (something like [mesos](https://github.com/gamozolabs/mesos) but much smaller), or using Intel Processor Trace. Intel PT is implemented using KVM-PT, a modified linux kernel used by [kAFL](https://github.com/IntelLabs/kAFL) which allows tracing virtual CPUs (you can see the paper [here](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf)). Packet decoding is done using [libxdc](https://github.com/klecko/libxdc), also released by Sergej ([@ms_s3c](https://twitter.com/ms_s3c)) and Cornelius ([@is_eqv](https://twitter.com/is_eqv)).

```
kvm-fuzz: fuzz x86_64 closed-source applications with hardware acceleration

Usage:
  kvm-fuzz [ options ] -- /path/to/fuzzed_binary [ args ]

Available options:
      --minimize-corpus    Set corpus minimization mode
      --minimize-crashes   Set crashes minimization mode
  -j, --jobs arg           Number of threads to use (default: 8)
  -m, --memory arg         Virtual machine memory limit (default: 8M)
  -k, --kernel path        Kernel path (default: ./kernel/kernel)
  -i, --input dir          Input folder (initial corpus) (default: ./in)
  -o, --output dir         Output folder (corpus, crashes, etc) (default: ./out)
  -f, --file path          Memory loaded files for the target. Set once for
                           each file, or as a list: -f file1,file2
  -b, --basic-blocks path  Path to file containing a list of basic blocks for
                           code coverage. Default value is
                           basic_blocks_<BinaryMD5Hash>.txt
  -s, --single-input path  Path to single input file. A single run will be
                           performed with this input.
  -h, --help               Print usage

```

## Is this fast?
It should be. As it uses KVM virtualization, execution speed should be near-native. However, it doesn't run Linux, but a much smaller kernel that attempts to emulate it. This results in less time spent executing in kernel mode, simply because we execute less instructions. As an example of this, this graph represents how many instructions are executed in two different runs of readelf and tiff2rgba in both kernel and user mode, running natively vs inside the VM. Every measure is from `main` until process calls `exit`.

![](https://i.imgur.com/3eny8vj.png)

In average, in each execution the VM ran 78% less of kernel instructions, and 37% less of total instructions than Linux. The experiment was probably not very rigorous, but it gives an idea.

I've also compared the fuzzing speed of kvm-fuzz to AFL++ targetting libtiff. AFL++ ran libtiff compiled with afl-clang-fast, using persistent mode and shared memory (as described [here](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)), while kvm-fuzz followed a similar setup (just running the fuzzed function and writing the input file into the VM's memory) with the non-instrumented library using basic block coverage. AFL++ was between 20% and 50% faster depending on the run. It should also be noted that there are a lot of differences between both: kvm-fuzz resets the guest memory after each execution and doesn't require source; AFL++ gets full-edge coverage and has a better mutator, etc.

## Notes
This isn't ready to be used yet. Building the kernel requires a cross compiler, and using Intel PT requires building a custom Linux kernel (KVM-PT with some little changes). Wait for it! :)