set(CMAKE_C_COMPILER "x86_64-elf-gcc")
set(CMAKE_CXX_COMPILER "x86_64-elf-g++")
set(CMAKE_ASM_NASM_OBJECT_FORMAT "elf64")
enable_language(ASM_NASM)

set(LINKER_FILE "${CMAKE_CURRENT_SOURCE_DIR}/linker.ld")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffreestanding -static -Wall -mno-sse")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti -masm=intel")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpic -fpie -fno-use-cxa-atexit")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG=1")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib -lgcc")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T ${LINKER_FILE}")

set(SOURCE_FILES
	src/apic/apic.cpp
	src/fs/file_description.cpp
	src/fs/file_manager.cpp
	src/gdt/gdt.cpp
	src/hypercalls.cpp
	src/idt/default_isrs.asm
	src/idt/idt.cpp
	src/interrupts.cpp
	src/libcpp/libcpp.cpp
	src/libcpp/printf.cpp
	src/libcpp/safe_mem.cpp
	src/main.cpp
	src/mem/mem.cpp
	src/mem/page_walker.cpp
	src/pit/pit.cpp
	src/process.cpp
	src/scheduler.cpp
	src/syscall/syscall.cpp
	src/syscalls/access.cpp
	src/syscalls/brk.cpp
	src/syscalls/dup.cpp
	src/syscalls/fcntl.cpp
	src/syscalls/ioctl.cpp
	src/syscalls/kill.cpp
	src/syscalls/lseek.cpp
	src/syscalls/mmap.cpp
	src/syscalls/open.cpp
	src/syscalls/prctl.cpp
	src/syscalls/prlimit.cpp
	src/syscalls/read.cpp
	src/syscalls/readlink.cpp
	src/syscalls/stat.cpp
	src/syscalls/sysinfo.cpp
	src/syscalls/time.cpp
	src/syscalls/uname.cpp
	src/syscalls/write.cpp
	src/user.cpp
)

include_directories(
	include
	include/STL
	include/linux
	include/linux/x86_64-linux-gnu
)

set_source_files_properties(src/interrupts.cpp PROPERTIES COMPILE_FLAGS
	-mgeneral-regs-only
)

add_executable(kernel ${SOURCE_FILES})
set_target_properties(kernel PROPERTIES LINK_DEPENDS "${LINKER_FILE}")
