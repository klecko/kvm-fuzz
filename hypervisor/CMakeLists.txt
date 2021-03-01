set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -no-pie")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
set(SOURCE_FILES src/main.cpp src/mmu.cpp src/vm.cpp src/elf_parser.cpp
                 src/corpus.cpp
                 src/page_walker.cpp src/hypercalls.cpp)
add_executable(kvm-fuzz ${SOURCE_FILES})
include_directories(include)