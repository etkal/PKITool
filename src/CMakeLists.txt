cmake_minimum_required(VERSION 3.24)

add_executable(pkitool)

target_sources(pkitool PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/PKITool.cpp
    ${CMAKE_CURRENT_LIST_DIR}/CCertOperation.cpp
    ${CMAKE_CURRENT_LIST_DIR}/CCertificate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/COpenSSL.cpp
)

target_link_libraries(pkitool openssl::openssl)

configure_file(${CMAKE_CURRENT_LIST_DIR}/Resources/pkitool.ini
    ${CMAKE_CURRENT_BINARY_DIR}/pkitool.ini COPYONLY)
configure_file(${CMAKE_CURRENT_LIST_DIR}/Resources/pkitool.txt
    ${CMAKE_CURRENT_BINARY_DIR}/pkitool.txt COPYONLY)
configure_file(${CMAKE_CURRENT_LIST_DIR}/Resources/test.sh
    ${CMAKE_CURRENT_BINARY_DIR}/test.sh COPYONLY)
