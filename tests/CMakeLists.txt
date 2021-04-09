set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
set(SOURCE_FILES
	tests.cpp
	brk.cpp
	files.cpp
	thread_local.cpp
	uname.cpp
	readlink.cpp
	mmap.cpp
)
add_executable(tests ${SOURCE_FILES})