cmake_minimum_required(VERSION 3.24)

project(PKITool CXX)

find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(src)
