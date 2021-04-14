## Hypervisor
This is the hypervisor. It implements the fuzzing process.

First, it creates a Virtual Machine using KVM, loads the target binary and the kernel into its memory, sets its registers and runs it. Inside the VM, the kernel will start running, set up everything it needs and finally jump to the target binary. Execution will stop when it gets to a specified point, for example function `main`. Then, the hypervisor will create some threads. Each one of them will copy the VM into a new one, and then run the fuzz loop in parallel using this new VM:
1. Get a new mutated input from the corpus.
2. Write input content into VM's memory.
3. Run the VM until guest kernel notifies us the run has finished (because the target binary called exit, or because a crash occurred).
4. Report the code coverage we got in the run. If last input triggered some new interesting code, the corpus will save it for further mutating it.
5. Reset the VM to the state of the first VM (at main).

There is also be a thread in charge of displaying useful stats, such as fuzz cases per second, total coverage measured, number of crashes found, etc.