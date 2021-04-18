set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
set(SOURCE_FILES
	brk.cpp
	dup.cpp
	files.cpp
	mmap.cpp
	readlink.cpp
	tests.cpp
	thread_local.cpp
	uname.cpp
)
add_executable(tests ${SOURCE_FILES})