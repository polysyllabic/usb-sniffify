get_filename_component(PARENT_DIR ../ ABSOLUTE)

add_executable(passthrough EXCLUDE_FROM_ALL passthrough.cpp)
target_include_directories(passthrough PUBLIC ${PARENT_DIR}/include ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(passthrough sniffify ${LIBUSB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} m)

add_executable(libusbhax EXCLUDE_FROM_ALL libusbhax.c)
target_include_directories(libusbhax PUBLIC ${PARENT_DIR}/include ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(libusbhax ${LIBUSB_LIBRARIES})

#add_executable(hid hid.c)
#target_include_directories(hid PUBLIC ${PARENT_DIR}/include ${LIBUSB_INCLUDE_DIRS})
#target_link_libraries(hid sniffifyc ${LIBUSB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

#add_executable(passthroughc EXCLUDE_FROM_ALL passthrough.c)
#target_include_directories(passthroughc PUBLIC ${PARENT_DIR}/include ${LIBUSB_INCLUDE_DIRS})
#target_link_libraries(passthroughc sniffifyc ${LIBUSB_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} m)
