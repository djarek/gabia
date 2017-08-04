cmake_minimum_required(VERSION 2.6)
project(gabia CXX)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(cmake/ClangTools.cmake)

add_subdirectory(examples/server/)

install(DIRECTORY include/ DESTINATION include)
