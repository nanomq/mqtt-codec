cmake_minimum_required(VERSION 3.13)

project(mqtt-codec)

option(DEBUG "This is a default option for DEBUG" OFF)
option(EXAMPLE "This is a
default option for EXAMPLE" OFF)

if(DEBUG)
  set(CMAKE_BUILD_TYPE "Debug")
  if(APPLE)
    set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} -Wall -g -fsanitize=address")
  else()
    set(CMAKE_C_FLAGS
      "${CMAKE_C_FLAGS} -Wall -g -fsanitize=address -fsanitize=leak")
  endif()
  add_definitions(-DDEBUG)
endif(DEBUG)

set(SOURCES 
  src/mqtt_codec.c  
  src/mqtt_codec.h
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(mqtt-codec ${SOURCES})

if(EXAMPLE)
  add_executable(mqtt-codec-test test/example.c )
  target_link_libraries(mqtt-codec-test mqtt-codec)
  target_link_libraries(mqtt-codec-test m)
endif(EXAMPLE)

if(NOT DEBUG)
  target_compile_options(mqtt-codec PUBLIC -O3 -Os -g)
endif()