cmake_minimum_required(VERSION 3.24)

project(PKITool CXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 20)

add_executable(pkitool)

target_sources(pkitool PUBLIC
    src/PKITool.cpp
    src/CCertOperation.cpp
    src/CCertificate.cpp
    src/COpenSSL.cpp
)

target_link_libraries(pkitool openssl::openssl)

configure_file(src/Resources/pkitool.ini
    ${CMAKE_BINARY_DIR}/pkitool.ini COPYONLY)
configure_file(src/Resources/pkitool.txt
    ${CMAKE_BINARY_DIR}/pkitool.txt COPYONLY)
configure_file(src/Resources/test.sh
    ${CMAKE_BINARY_DIR}/test.sh COPYONLY)
