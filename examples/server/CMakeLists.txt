set(CMAKE_CXX_COMPILER_FLAGS "-flto ${CMAKE_CXX_COMPILER_FLAGS}  -fsanitize=address")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-s ${CMAKE_CXX_FLAGS_MINSIZEREL}")
add_compile_options(-Wall
                    -Wextra
                    -pedantic
                    -std=c++14
                    -fvisibility=hidden
                    -pipe
                    )

find_package(Boost 1.58.0 COMPONENTS system coroutine REQUIRED)

add_executable(gabia_server_example main.cpp server.cpp)
target_include_directories(gabia_server_example PUBLIC ../../../Beast/include/)
target_include_directories(gabia_server_example PUBLIC ../../../GSL/include/)
target_include_directories(gabia_server_example PUBLIC ../../../json/src/)
target_include_directories(gabia_server_example PUBLIC src/)
target_include_directories(gabia_server_example PUBLIC ../../include/)
target_link_libraries(gabia_server_example ${Boost_LIBRARIES})
target_link_libraries(gabia_server_example wolfssl)
target_link_libraries(gabia_server_example pthread)
