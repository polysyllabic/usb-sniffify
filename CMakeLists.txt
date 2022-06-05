cmake_minimum_required(VERSION 3.15)

project(usb-sniffily VERSION 1.1
                 DESCRIPTION "USB sniffer, forwarder, injector for Raspberry Pi 4"
                 LANGUAGES CXX C)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "Do not build in-source. Please remove CMakeCache.txt and the CMakeFiles/ directory. Then build out-of-source.")
endif()
               
find_package(PkgConfig)
pkg_check_modules(LIBUSB REQUIRED libusb-1.0)

include(FetchContent)
FetchContent_Declare(
  plog
  GIT_REPOSITORY https://github.com/SergiusTheBest/plog.git
  GIT_TAG        origin/master
)

find_package(Threads REQUIRED)

add_library(sniffify  src/raw-helper.cpp
            src/raw-gadget.cpp
            src/raw-gadget-passthrough.cpp
            include/raw-gadget.hpp
            include/raw-helper.h)

target_include_directories(sniffify PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${LIBUSB_INCLUDE_DIRS} 
  ${plog_SOURCE_DIR}/include)

target_compile_definitions(sniffify PRIVATE PLOG_GLOBAL)
#add_library(sniffifyc EXCLUDE_FROM_ALL src/raw-helper.c
#            include/raw-helper.h)
#target_include_directories(sniffifyc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
#            ${LIBUSB_INCLUDE_DIRS})
          
add_subdirectory(examples EXCLUDE_FROM_ALL)