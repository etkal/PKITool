cmake_minimum_required(VERSION 3.24)

project(pkitool C CXX)

add_executable(pkitool)
message(STATUS "[" ${HOME} "]")

message(STATUS "test 1 2 3")

target_sources(pkitool PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/PKITool.cpp
    ${CMAKE_CURRENT_LIST_DIR}/CCertOperation.cpp
    ${CMAKE_CURRENT_LIST_DIR}/CCertificate.cpp
    ${CMAKE_CURRENT_LIST_DIR}/COpenSSL.cpp
)
        
target_include_directories(pkitool PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/ssl/include
)

target_link_libraries(pkitool libcrypto.a
)

