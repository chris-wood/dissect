cmake_minimum_required(VERSION 3.3)
project(dissect)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c99")

set(SOURCE_FILES
    src/packet.c
    src/packet.h
    src/buffer.c
    src/buffer.h
    src/tlv.c
    src/tlv.h
    src/capture.c
    src/capture.h
    src/reporter.c
    src/reporter.h
    src/types.c
    src/types.h
    src/cJSON.c
    src/cJSON.h
    src/omap.c
    src/omap.h
    src/util.h
    )

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(CMAKE_C_FLAGS_DEBUG_INIT "-g")

include_directories(src)

add_library(libdissect ${SOURCE_FILES})
add_executable(dissect src/dissect.c)
target_link_libraries(dissect libdissect pcap)

add_executable(test_packet src/test/test_packet.c)
target_link_libraries(test_packet libdissect cmocka pcap)
