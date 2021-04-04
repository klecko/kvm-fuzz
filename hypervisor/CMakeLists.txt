set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall")
set(CMAKE_CXX_FLAGS_STATIC "-static -Wl,--whole-archive \
                            -lpthread -Wl,--no-whole-archive")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_STATIC}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -no-pie -DDEBUG=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
set(SOURCE_FILES src/main.cpp src/mmu.cpp src/vm.cpp src/elf_parser.cpp
                 src/corpus.cpp src/args.cpp src/utils.cpp
                 src/page_walker.cpp src/hypercalls.cpp)
add_executable(kvm-fuzz ${SOURCE_FILES})
target_link_libraries(kvm-fuzz xdc dwarf elf crypto)
include_directories(include)
