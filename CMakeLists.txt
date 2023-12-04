cmake_minimum_required(VERSION 3.0)
project(elf)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_C_COMPILER gcc)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

add_executable(elf src/elf.c)
target_link_libraries(elf pthread)
target_link_directories(elf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_include_directories(elf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_custom_command(TARGET elf POST_BUILD COMMAND ${CMAKE_STRIP} ${CMAKE_CURRENT_SOURCE_DIR}/bin/elf)

# another project that compiles a shared object
add_library(elflib SHARED src/ldkit.c)
target_include_directories(elflib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# set output directory for shared library
set_target_properties(elflib PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
target_include_directories(elflib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(elflib pcap)

add_custom_command(TARGET elflib POST_BUILD COMMAND ${CMAKE_STRIP} ${CMAKE_CURRENT_SOURCE_DIR}/bin/libelflib.so)