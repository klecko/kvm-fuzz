cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_COMPILER g++)

project(kvm-fuzz)

add_subdirectory(kernel)
add_subdirectory(hypervisor)
add_subdirectory(tests EXCLUDE_FROM_ALL)
