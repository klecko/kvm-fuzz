set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
set(SOURCE_FILES
	brk.cpp
	dup.cpp
	files.cpp
	getcwd.cpp
	mmap.cpp
	readlink.cpp
	socket.cpp
	stdin.cpp
	tests.cpp
	thread_local.cpp
	uname.cpp
)
add_executable(tests ${SOURCE_FILES})