# kvm-fuzz
The goal is to emulate and fuzz x86_64 binaries using KVM. The original idea was simply running userspace code inside the virtual machine, generating a VM exit when it called a syscall, which was then satisfied by the hypervisor. However, performance was bad when there were a significant amount of syscalls because VM exits are very expensive. In order to solve this, syscalls are now handled in the kernel inside the VM, so the only VM exit is at the end of each run.

Code coverage is achieved either using breakpoint-based coverage (something like [mesos](https://github.com/gamozolabs/mesos) but much smaller), or using Intel Processor Trace. Intel PT is implemented using KVM-PT, a modified linux kernel used by [kAFL](https://github.com/IntelLabs/kAFL) which allows tracing virtual CPUs (you can see the paper [here](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf)). Packet decoding is done using [libxdc](https://github.com/klecko/libxdc), also released by Sergej ([@ms_s3c](https://twitter.com/ms_s3c)) and Cornelius ([@is_eqv](https://twitter.com/is_eqv)).

```
kvm-fuzz: fuzz x86_64 closed-source applications with hardware acceleration

Usage:
  kvm-fuzz [ options ] -- /path/to/fuzzed_binary [ args ]

Available options:
      --minimize-corpus     Set corpus minimization mode
      --minimize-crashes    Set crashes minimization mode
  -j, --jobs n              Number of threads to use (default: 8)
  -m, --memory arg          Virtual machine memory limit (default: 8M)
  -t, --timeout ms          Timeout for each in run in milliseconds, or 0 for no
                            timeout (default: 2)
  -k, --kernel path         Kernel path (default: ./zig-out/bin/kernel)
  -i, --input dir           Input folder (initial corpus) (default: ./in)
  -o, --output dir          Output folder (corpus, crashes, etc) (default: ./out)
  -f, --file path           Memory loaded files for the target. Set once for
                            each file: -f file1 -f file2
  -s, --single-run [=path]  Perform a single run, optionally specifying an
                            input file
  -T, --tracing type        Enable syscall tracing. Type can be kernel or user
      --tracing-unit unit   Tracing unit. It can be instructions or cycles (default cycles)
  -h, --help                Print usage
```

## Dependencies
Building requires a recent build of Zig, which you can get from [here](https://ziglang.org/download/). Zig is in charge of compiling the kernel (in Zig) and the hypervisor and the tests (in C++). It also acts as build system. Other dependencies are `libdwarf`, `libelf` and `libssl`, which you can install from your package manager:
```
sudo apt install libdwarf-dev libelf-dev libssl-dev
```

In order to fuzz using breakpoints-based coverage, if you want the breakpoints file to be generated automatically you'll need `python3` and `angr`:
```bash
sudo apt install python3
python3 -m pip install angr
```

Finally, in order to fuzz using Intel PT coverage, you will need [libxdc](https://github.com/klecko/libxdc) and [kAFL](https://github.com/IntelLabs/kAFL) (not tested with the more recent [KVM-Nyx](https://github.com/nyx-fuzz/KVM-Nyx) yet).

## Building and running tests
Build kernel and hypervisor, disabling coverage and enabling guest binary output:
```
zig build -Dcoverage=none -Denable-guest-output
```

Build tests:
```
zig build tests
```

Run tests on your host machine:
```
scripts/run_tests_on_linux.sh
```

Run tests inside the hypervisor (running kvm-fuzz requires having a non-empty seed corpus, which is by default located at `./in`):
```
mkdir in
touch in/1
scripts/run_tests_on_kvm-fuzz.sh
```
This simply runs the tests binary on kvm-fuzz, specifying some options such as single run and no timeout. If everything went well you should see something like:
```
[KERNEL] ===============================================================================
[KERNEL] All tests passed (2378 assertions in 44 test cases)
[KERNEL]
Run ended with reason Exit
```

## Fuzzing example
Now you should be ready to start fuzzing! Let's fuzz readelf using `ls` binary as seed. This time we don't want the guest to print to the terminal, so we leave that option disabled and build again. Run kvm-fuzz setting 16 MB of memory for the VMs, and 5 ms of timeout:
```
$ zig build -Dcoverage=none
$ rm in/1
$ cp /bin/ls in/
$ zig-out/bin/kvm-fuzz -m 16M -t 5 -- /bin/readelf -a input
Number of threads: 8
Total files read: 1
Max mutated input size: 1421440
Ready to run!
[KERNEL] [default] [info] hello from zig
[KERNEL] [user] [info] Jumping to user at 0x400000001100 with rsp 0x7ffffffffe70!
[...]
Performing first runs...
Set corpus mode: Normal. Output directories will be ./out/corpus and ./out/crashes. Seed corpus coverage: 0
Creating threads...
[1.000] cases: 6265, mips: 10807.154, fcps: 6264.102, cov: 0, corpus: 1/138.812KB, unique crashes: 0 (total: 0), timeouts: 3, no new cov for: 1.000
        vm exits: 1.000 (hc: 1.000, cov: 0.000, debug: 0.000), reset pages: 137.765
        run: 0.864, reset: 0.045, mut: 0.081, set_input: 0.011, report_cov: 0.000
        kvm: 0.863, hc: 0.000, update_cov: 0.000, mut1: 0.007, mut2: 0.075
[2.000] cases: 12907, mips: 11112.763, fcps: 6640.934, cov: 0, corpus: 1/138.812KB, unique crashes: 0 (total: 0), timeouts: 3, no new cov for: 2.000
        vm exits: 1.000 (hc: 1.000, cov: 0.000, debug: 0.000), reset pages: 137.109
        run: 0.866, reset: 0.044, mut: 0.079, set_input: 0.011, report_cov: 0.000
        kvm: 0.865, hc: 0.000, update_cov: 0.000, mut1: 0.007, mut2: 0.072
[3.000] cases: 19397, mips: 11125.964, fcps: 6489.186, cov: 0, corpus: 1/138.812KB, unique crashes: 0 (total: 0), timeouts: 4, no new cov for: 3.000
        vm exits: 1.000 (hc: 1.000, cov: 0.000, debug: 0.000), reset pages: 137.286
        run: 0.865, reset: 0.044, mut: 0.080, set_input: 0.011, report_cov: 0.000
        kvm: 0.865, hc: 0.000, update_cov: 0.000, mut1: 0.007, mut2: 0.074
```

We can see some useful stats: total cases, millions of user instructions executed per seconds, fuzz cases per second, corpus size, some time tracing for profiling, etc.

Build in release mode with breakpoints-based coverage (the default) and try again:
```
$ zig build -Drelease-fast
$ zig-out/bin/kvm-fuzz -m 16M -t 5 -- /bin/readelf -a input
[...]
[3.001] cases: 35001, mips: 11669.951, fcps: 11765.726, cov: 2684, corpus: 143/28689.814KB, unique crashes: 0 (total: 0), timeouts: 4, no new cov for: 0.000
        vm exits: 1.031 (hc: 1.000, cov: 0.000, debug: 0.031), reset pages: 150.626
        run: 0.541, reset: 0.161, mut: 0.242, set_input: 0.055, report_cov: 0.001
        kvm: 0.540, hc: 0.000, update_cov: 0.000, mut1: 0.091, mut2: 0.150
```

We can see we are spending 24% of the time mutating inputs. In order to improve fuzzing speed, we can reduce this using smaller seeds. In my case, `/bin/ls` weighs 139KB, while `/bin/parallel` weighs only 14KB. Set it as single seed and run again:
```
$ rm in/*
$ cp /bin/parallel in
$ zig-out/bin/kvm-fuzz -m 16M -t 5 -- /bin/readelf -a input
[...]
[3.001] cases: 88147, mips: 16667.261, fcps: 31502.726, cov: 3030, corpus: 238/5874.473KB, unique crashes: 0 (total: 0), timeouts: 4, no new cov for: 0.000
        vm exits: 1.014 (hc: 1.000, cov: 0.000, debug: 0.014), reset pages: 94.269
        run: 0.838, reset: 0.102, mut: 0.052, set_input: 0.007, report_cov: 0.001
        kvm: 0.837, hc: 0.000, update_cov: 0.000, mut1: 0.010, mut2: 0.041
```
We can see some extra performance (31k fcps now vs 11k fcps before)

## Another fuzzing example
Let's fuzz the toy program `vuln.c`, found [here](https://gist.github.com/klecko/cb8e04c1ec1c147fce87a206067676c3). It reads the contents of a file, and if it passes some simple checks (the file starts with `GOTTAGOFAST!`), then it crashes. Let's compile it statically for extra perf, and with debug info so we can have source information printed with stacktraces. Set a small string as seed, and start fuzzing:
```
$ gcc vuln.c -static -g -o vuln
$ rm in/*
$ echo AAAAAAAAA > in/1
$ zig-out/bin/kvm-fuzz -- ./vuln input
```

We can see how the coverage increases as it finds inputs that passes the checks, and after some seconds it finds the crash:
```
$ zig-out/bin/kvm-fuzz -- ./vuln input
[...]
Creating threads...
[1.000] cases: 318683, mips: 163.344, fcps: 318645.655, cov: 133, corpus: 8/0.308KB, unique crashes: 0 (total: 0), timeouts: 0, no new cov for: 0.000
        vm exits: 1.006 (hc: 1.000, cov: 0.000, debug: 0.006), reset pages: 24.115
        run: 0.645, reset: 0.299, mut: 0.040, set_input: 0.011, report_cov: 0.003
        kvm: 0.639, hc: 0.001, update_cov: 0.000, mut1: 0.009, mut2: 0.027
[2.000] cases: 653249, mips: 171.672, fcps: 334521.378, cov: 133, corpus: 8/0.308KB, unique crashes: 0 (total: 0), timeouts: 0, no new cov for: 1.000
        vm exits: 1.000 (hc: 1.000, cov: 0.000, debug: 0.000), reset pages: 24.115
        run: 0.642, reset: 0.304, mut: 0.038, set_input: 0.011, report_cov: 0.003
        kvm: 0.636, hc: 0.001, update_cov: 0.000, mut1: 0.009, mut2: 0.027
[3.000] cases: 979854, mips: 167.977, fcps: 326559.700, cov: 135, corpus: 10/0.439KB, unique crashes: 0 (total: 0), timeouts: 0, no new cov for: 0.000
        vm exits: 1.000 (hc: 1.000, cov: 0.000, debug: 0.000), reset pages: 24.115
        run: 0.643, reset: 0.301, mut: 0.038, set_input: 0.012, report_cov: 0.003
        kvm: 0.638, hc: 0.001, update_cov: 0.000, mut1: 0.009, mut2: 0.028
[4.001] cases: 1313282, mips: 172.262, fcps: 333379.723, cov: 137, corpus: 12/0.593KB, unique crashes: 0 (total: 0), timeouts: 0, no new cov for: 0.000
        vm exits: 1.000 (hc: 1.000, cov: 0.000, debug: 0.000), reset pages: 24.115
        run: 0.636, reset: 0.306, mut: 0.041, set_input: 0.011, report_cov: 0.003
        kvm: 0.630, hc: 0.001, update_cov: 0.000, mut1: 0.009, mut2: 0.031

[CRASH: OutOfBoundsWrite] RIP: 0x401dc3, address: 0xdeadbeef
rip: 0x0000000000401dc3
rax: 0x00000000deadbeef  rbx: 0x0000000000400518  rcx: 0x00000000004511e7  rdx: 0x0000000000000059
rsi: 0x0000000000000059  rdi: 0x00007ffffffff930  rsp: 0x00007ffffffff900  rbp: 0x00007ffffffff900
r8:  0x0000000000498600  r9:  0x0000000000000009  r10: 0x0000000000000000  r11: 0x0000000000000246
r12: 0x0000000000402f80  r13: 0x0000000000000000  r14: 0x00000000004c0018  r15: 0x0000000000000000
rflags: 0x0000000000010246

#0 0x0000000000401dc3 in vuln + 0xde at /home/klecko/kvm-fuzz/vuln.c:15
#1 0x0000000000401ed9 in main + 0x10b at /home/klecko/kvm-fuzz/vuln.c:40
#2 0x0000000000402710 in __libc_start_main + 0x490
#3 0x0000000000401bee in _start + 0x2e
```
The crash is in `out/crashes`. We can verify it starts with our crash string:
```
$ cat out/crashes/OutOfBoundsWrite_0x401dc3_0xdeadbeef
GOTTAGOFAST!cTTTTTTTa���aaaaaaaɄ�K
```

Now we can try the crash minimization mode. Move the crash to the input folder and run kvm-fuzz with `--minimize-crashes`:
```
$ rm in/1
$ mv out/crashes/OutOfBoundsWrite_0x401dc3_0xdeadbeef in/crash
$ zig-out/bin/kvm-fuzz --minimize-crashes -- ./vuln input
[...]
Performing first runs...
Set corpus mode: Crashes Minimization. Output directory will be ./out/minimized_crashes
Creating threads...
[1.000] cases: 326009, mips: 164.344, fcps: 325935.693, cov: 0, corpus: 1/0.012KB, unique crashes: 0 (total: 8), timeouts: 0, no new cov for: 1.000
        vm exits: 1.006 (hc: 1.000, cov: 0.000, debug: 0.006), reset pages: 24.100
        run: 0.648, reset: 0.302, mut: 0.034, set_input: 0.011, report_cov: 0.001
        kvm: 0.641, hc: 0.001, update_cov: 0.000, mut1: 0.013, mut2: 0.019
```
We can see that in the first second the corpus was already reduced to 12 bytes, which is the minimum for crashing.
```
$ cat out/minimized_crashes/crash_min
GOTTAGOFAST!
```

## Is this fast?
It should be. As it uses KVM virtualization, execution speed should be near-native. However, it doesn't run Linux, but a much smaller kernel that attempts to emulate it. This results in less time spent executing in kernel mode, simply because we execute less instructions. As an example of this, this graph represents how many instructions are executed in two different runs of readelf and tiff2rgba in both kernel and user mode, running natively vs inside the VM. Every measure is from `main` until process calls `exit`.

![](https://i.imgur.com/3eny8vj.png)

In average, in each execution the VM ran 78% less of kernel instructions, and 37% less of total instructions than Linux. The experiment was probably not very rigorous, but it gives an idea.

I've also compared the fuzzing speed of kvm-fuzz to AFL++ targetting libtiff. AFL++ ran libtiff compiled with afl-clang-fast, using persistent mode and shared memory (as described [here](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)), while kvm-fuzz followed a similar setup (just running the fuzzed function and writing the input file into the VM's memory) with the non-instrumented library using basic block coverage. AFL++ was between 20% and 50% faster depending on the run. It should also be noted that there are a lot of differences between both: kvm-fuzz resets the guest memory after each execution and doesn't require source; AFL++ gets full-edge coverage and has a better mutator, etc.

## Notes
This is very work in progress. The kernel only supports very simple programs. It has near zero real world utility, but it is very fun!
