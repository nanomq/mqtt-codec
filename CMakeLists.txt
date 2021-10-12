cmake_minimum_required(VERSION 2.8.8)

project(mqtt-codec)

option(STAIC_LIB "This is a default option for build static lib" ON)
option(SHARE_LIB "This is a default option for build dynamic lib" ON)
option(DEBUG "This is a default option for DEBUG" OFF)
option(EXAMPLE "This is a
default option for EXAMPLE" OFF)

if(DEBUG)
  message("DEBUG: ON")
  set(CMAKE_BUILD_TYPE "Debug")
  set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} -Wall -g -fsanitize=address -fsanitize=leak")
  add_definitions(-DDEBUG)
endif(DEBUG)

set(SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/mqtt_basic.c
            ${CMAKE_CURRENT_SOURCE_DIR}/src/mqtt_codec.c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

if(STAIC_LIB)
  message("Build static lib: ON")
  add_library(mqtt-codec SHARED ${SOURCES})
endif(STAIC_LIB)

if(SHARE_LIB)
  message("Build dynamic lib: ON")
  add_library(mqtt-codec-static STATIC ${SOURCES})
endif()

if(EXAMPLE)
  message("EXAMPLE: ON")
  add_executable(mqtt-codec-test test/example.c)

  target_link_libraries(mqtt-codec-test mqtt-codec)
  target_link_libraries(mqtt-codec-test m)
endif(EXAMPLE)
