set(CMAKE_C_COMPILER "x86_64-elf-gcc")
set(CMAKE_CXX_COMPILER "x86_64-elf-g++")
set(LINKER_FILE "${CMAKE_CURRENT_SOURCE_DIR}/linker.ld")

# Add linux header files, as we are emulating a linux kernel
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffreestanding -static -Wall -mno-sse \
	-fno-exceptions -fno-rtti -masm=intel -fpic -fpie -fno-use-cxa-atexit \
	-I /usr/include/x86_64-linux-gnu -I /usr/include")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib \
	-lgcc -T ${LINKER_FILE}")
set(SOURCE_FILES src/main.cpp src/libcpp.cpp src/hypercalls.cpp src/kernel.cpp
                 src/file.cpp src/syscalls.cpp)
add_executable(kernel ${SOURCE_FILES})
include_directories(include include/STL)
set_target_properties(kernel PROPERTIES LINK_DEPENDS "${LINKER_FILE}")
