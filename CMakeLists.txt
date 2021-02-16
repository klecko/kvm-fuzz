cmake_minimum_required(VERSION 3.5)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_COMPILER g++)

project(kvm-fuzz)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -no-pie")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

set(SOURCE_FILES src/main.cpp src/mmu.cpp src/vm.cpp src/elf_parser.cpp
                 src/syscalls.cpp src/file.cpp src/corpus.cpp
                 src/page_walker.cpp)
include_directories(include)

add_executable(kvm-fuzz ${SOURCE_FILES})
