cmake_minimum_required(VERSION 3.5.0)
set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_C_STANDARD 99)
project (yiikplay_test VERSION 0.1.0 LANGUAGES C)

add_executable (yiikplay_test airplay.c airplay_mdns.c mdns.c)

IF (WIN32)
target_link_libraries(yiikplay_test ws2_32)
ENDIF()