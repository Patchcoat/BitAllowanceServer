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

# add binary tree to the search path
include_directories("${PROJECT_BINARY_DIR}")

# add executable
add_executable(server server.c)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(server OpenSSL::SSL)
