cmake_minimum_required(VERSION 3.13)

project(PKITool)

#find_package(OpenSSL 1.1 EXACT)

include_directories(pkitool PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/PKITool
    ${CMAKE_CURRENT_LIST_DIR}/ssl/include
)

link_directories(pkitool
    ${CMAKE_CURRENT_LIST_DIR}/ssl/lib
)

add_subdirectory(PKITool)

