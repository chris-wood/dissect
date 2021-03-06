cmake_minimum_required(VERSION 2.8.7)
project(dissect)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu99")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

option(COVERALLS "Generate coveralls data" OFF)

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
    src/processor.c
    src/processor.h
    src/digester.c
    src/digester.h
    src/lib-sha256.c
    src/lib-sha256.h
    src/types.c
    src/types.h
    src/cJSON.c
    src/cJSON.h
    src/omap.c
    src/omap.h
    src/util.h
    )

if (COVERALLS)
    include(Coveralls)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")

    set(COVERAGE_SOURCES ${SOURCE_FILES})
    coveralls_setup(
        "${COVERAGE_SOURCES}"
        ON
        "${PROJECT_SOURCE_DIR}/cmake/")
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(CMAKE_C_FLAGS_DEBUG_INIT "-g")

include_directories(src)

add_library(libdissect ${SOURCE_FILES})
set_property(TARGET libdissect PROPERTY C_STANDARD 99)

add_executable(dissect src/dissect.c)
target_link_libraries(dissect libdissect pcap m)
set_property(TARGET dissect PROPERTY C_STANDARD 99)

#add_executable(test_packet src/test/test_packet.c)
#target_link_libraries(test_packet libdissect cmocka pcap m)
#set_property(TARGET test_packet PROPERTY C_STANDARD 99)
