# Just call zig build
if (CMAKE_BUILD_TYPE MATCHES Release)
	set(ZIG_RELEASE_OPTION -Drelease-fast)
endif()

add_custom_target(
	kernel
	ALL
	COMMAND zig build --build-file ${CMAKE_CURRENT_SOURCE_DIR}/build.zig
	                  --cache-dir ${CMAKE_CURRENT_BINARY_DIR}/zig-cache
	                  -p ${CMAKE_CURRENT_BINARY_DIR}
	                  ${ZIG_RELEASE_OPTION}
)