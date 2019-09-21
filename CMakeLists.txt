cmake_minimum_required(VERSION 3.13)
project(block_cipher C)

set(CMAKE_C_STANDARD 99)
set(SOURCE_FILES main.cpp)
set(OPENSSL_USE_STATIC_LIBS TRUE)

#set(INC_DIR /usr/include/openssl)
#set(LINK_DIR /usr/bin/openssl)
#
#include_directories(${INC_DIR})
#link_directories(${LINK_DIR})
#link_libraries(crypto)

find_package(OpenSSL REQUIRED)


add_executable(block_cipher main.c)

target_link_libraries(block_cipher OpenSSL::Crypto)