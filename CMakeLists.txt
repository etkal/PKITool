cmake_minimum_required(VERSION 3.24)

project(PKITool CXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 20)

add_library(pkitool_lib STATIC
    src/CCertOperation.cpp
    src/CCertificate.cpp
    src/COpenSSL.cpp
)
target_include_directories(pkitool_lib PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(pkitool_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)

add_executable(pkitool src/PKITool.cpp)
target_link_libraries(pkitool PRIVATE pkitool_lib)

enable_testing()

find_package(GTest CONFIG REQUIRED)

add_executable(pkitool_tests
        tests/pkitool_tests.cpp
)
target_include_directories(pkitool_tests PRIVATE src)
target_link_libraries(pkitool_tests GTest::gtest_main pkitool_lib OpenSSL::SSL OpenSSL::Crypto)
include(GoogleTest)
gtest_discover_tests(pkitool_tests)

configure_file(src/Resources/pkitool.ini
    ${CMAKE_BINARY_DIR}/pkitool.ini COPYONLY)
configure_file(src/Resources/pkitool.txt
    ${CMAKE_BINARY_DIR}/pkitool.txt COPYONLY)
configure_file(src/Resources/test.sh
    ${CMAKE_BINARY_DIR}/test.sh COPYONLY)
