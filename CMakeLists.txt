cmake_minimum_required (VERSION 2.6)
project(server)
# version
set (Server_VERSION_MAJOR 0)
set (Server_VERSION_MINOR 1)

# configure header
configure_file (
  "${PROJECT_SOURCE_DIR}/server.h.in"
  "${PROJECT_BINARY_DIR}/server.h"
  )

#SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
#list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_PREFIX}")

# add binary tree to the search path
include_directories("${PROJECT_BINARY_DIR}")
#include_directories(${MYSQL_INCLUDE_DIR})

# add executable
add_executable(server server.c)

# OpenSSL and MySQL
find_package(OpenSSL REQUIRED)
#find_package(MySQL REQUIRED)
target_link_libraries(server OpenSSL::SSL)
#target_link_libraries(server ${MYSQL_LIBS})
