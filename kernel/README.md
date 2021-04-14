## Kernel
This is the kernel. It implements the emulation part. It runs inside the VM, and is in charge of handling target binary syscalls and reporting crashes to the hypervisor.

When the VM starts, the kernel will first do some things it needs in order to work correctly, such as initiating its memory manager and registering the interrupt handlers and the syscall handler. Then, with the help of the hypervisor, it will get some information related to the target binary, such as the files it may need to open. Finally, it will jump to the target binary entry point and start executing it.

Whenever the target binary executes the instruction syscall, execution is transferred to the kernel syscall handler, which will emulate the behaviour of the syscall. If the syscall `exit` is ran, or if the guest binary causes a page fault, the hypervisor is notified and the whole VM is restored to start a new run.

**Disclaimer**: I have no idea about kernel development so this code is probably pretty bad. I'm currently learning about this world to make it better!
