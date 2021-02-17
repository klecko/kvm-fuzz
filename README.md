# kvm-fuzz
The idea is to emulate and fuzz x86-64 binaries using KVM. The virtual machine simply runs userspace code, generating a VM exit when it calls a syscall, which is then satisfied by us.

Despite having less control than emulating everything (instructions, memory accesses and permissions, etc), this approach seems to be simpler and faster. No more 100% CPU time in userspace though :(

Road to 100% CPU time in kernel??
