add_executable(gabia_server_example main.cpp server.cpp)
target_include_directories(gabia_server_example PRIVATE
    ../../../json/src/
    src/
)
target_compile_definitions(gabia_server_example PRIVATE
    BOOST_COROUTINES_NO_DEPRECATION_WARNING
)
target_link_libraries(gabia_server_example
    ${Boost_LIBRARIES}
    wolfssl
    pthread)
