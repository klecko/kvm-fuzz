set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
set(SOURCE_FILES
	brk.cpp
	dup.cpp
	fcntl.cpp
	files.cpp
	fork.cpp
	getcwd.cpp
	misc.cpp
	mmap.cpp
	readlink.cpp
	socket.cpp
	stdin.cpp
	tests.cpp
	thread_local.cpp
	uname.cpp
)
add_executable(tests ${SOURCE_FILES})