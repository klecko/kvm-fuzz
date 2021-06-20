set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -no-pie")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -march=native")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

option(DEBUG "Enable debug prints" OFF)
if(DEBUG)
	add_compile_definitions(DEBUG)
endif(DEBUG)

set(SOURCE_FILES
	src/args.cpp
	src/corpus.cpp
	src/elf_parser.cpp
	src/hypercalls.cpp
	src/main.cpp
	src/mmu.cpp
	src/page_walker.cpp
	src/utils.cpp
	src/vm.cpp
)

include_directories(include)

add_executable(kvm-fuzz ${SOURCE_FILES})
target_link_libraries(kvm-fuzz
	xdc
	dwarf
	elf
	crypto
)
