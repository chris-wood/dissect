cmake_minimum_required(VERSION 3.3)
project(dissect)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c99")

set(SOURCE_FILES src/packet.c src/packet.h src/buffer.c src/buffer.h src/util.h src/parser.c src/parser.h)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

include_directories(src)

add_library(libdissect ${SOURCE_FILES})
add_executable(dissect src/dissect.c ${SOURCE_FILES} src/parser.h)

