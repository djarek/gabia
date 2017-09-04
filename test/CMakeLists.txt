project (gabia_tests CXX)

function(add_gabia_test name)
    add_executable(${name} ${name}.cpp)
    target_compile_definitions(${name} PRIVATE
        BOOST_TEST_DYN_LINK
        BOOST_TEST_MAIN
    )
    target_compile_options(${name} PRIVATE
        -ftest-coverage
        -fprofile-arcs
    )
    target_link_libraries(${name}
        ${Boost_LIBRARIES}
        wolfssl
        -ftest-coverage
        -fprofile-arcs
    )
    add_test(
      ${name}
      ${name}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_property(TARGET ${name} PROPERTY FOLDER "gabia_tests")
endfunction()

add_subdirectory(gabia)
