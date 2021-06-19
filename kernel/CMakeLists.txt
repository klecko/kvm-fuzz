set(CMAKE_CXX_COMPILER "../../compiler/bin/x86_64-elf-g++")
set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
enable_language(ASM_NASM)

set(LINKER_FILE "${CMAKE_CURRENT_SOURCE_DIR}/linker.ld")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffreestanding -static -Wall -mno-sse")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti -masm=intel")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpic -fpie -fno-use-cxa-atexit")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mno-red-zone")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG=1")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -flto")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib -lgcc")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T ${LINKER_FILE}")

set(SOURCE_FILES
	src/fs/file_description.cpp
	src/fs/file_manager.cpp
	src/hypercalls.cpp
	src/interrupts.cpp
	src/libcpp
	src/libcpp/libcpp.cpp
	src/libcpp/libcpp.h
	src/libcpp/printf.cpp
	src/libcpp/printf.h
	src/libcpp/safe_mem.cpp
	src/libcpp/safe_mem.h
	src/libcpp/user_ptr.h
	src/main.cpp
	src/mem/address_space.cpp
	src/mem/heap.cpp
	src/mem/page_table.cpp
	src/mem/pmm.cpp
	src/mem/vmm.cpp
	src/process.cpp
	src/scheduler.cpp
	src/syscalls/access.cpp
	src/syscalls/brk.cpp
	src/syscalls/clone.cpp
	src/syscalls/dup.cpp
	src/syscalls/fcntl.cpp
	src/syscalls/getcwd.cpp
	src/syscalls/ioctl.cpp
	src/syscalls/kill.cpp
	src/syscalls/lseek.cpp
	src/syscalls/mmap.cpp
	src/syscalls/open.cpp
	src/syscalls/prctl.cpp
	src/syscalls/prlimit.cpp
	src/syscalls/read.cpp
	src/syscalls/readlink.cpp
	src/syscalls/socket.cpp
	src/syscalls/stat.cpp
	src/syscalls/sysinfo.cpp
	src/syscalls/time.cpp
	src/syscalls/uname.cpp
	src/syscalls/write.cpp
	src/user.cpp
	src/x86/apic/apic.cpp
	src/x86/gdt/gdt.cpp
	src/x86/idt/default_isrs.asm
	src/x86/idt/idt.cpp
	src/x86/perf/perf.cpp
	src/x86/pit/pit.cpp
	src/x86/syscall/syscall.cpp
)

include_directories(
	src
	src/STL
	linux
	linux/x86_64-linux-gnu
)

set_source_files_properties(src/interrupts.cpp PROPERTIES COMPILE_FLAGS
	-mgeneral-regs-only
)

add_executable(kernel ${SOURCE_FILES})
set_target_properties(kernel PROPERTIES LINK_DEPENDS "${LINKER_FILE}")
