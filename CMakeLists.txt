cmake_minimum_required(VERSION 2.6)
project(gabia CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(cmake/ClangTools.cmake)
include(CTest)
find_package(Boost 1.58.0 COMPONENTS system coroutine unit_test_framework REQUIRED)

#set(CMAKE_CXX_COMPILER_FLAGS "-flto ${CMAKE_CXX_COMPILER_FLAGS}  -fsanitize=address -fprofile-arcs -ftest-coverage")
#set(CMAKE_CXX_FLAGS_MINSIZEREL "-s ${CMAKE_CXX_FLAGS_MINSIZEREL}")
add_compile_options(
    -Wall
    -Wextra
    -pedantic
    -std=c++14
    -fvisibility=hidden
    -pipe
)

include_directories(include)
add_subdirectory(examples/server/)
install(DIRECTORY include/ DESTINATION include)

enable_testing()
add_subdirectory(test)




