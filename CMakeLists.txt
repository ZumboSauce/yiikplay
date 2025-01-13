cmake_minimum_required(VERSION 3.5.0)
set (CMAKE_BUILD_TYPE Debug)
set (CMAKE_C_STANDARD 99)
project (yiikplay VERSION 0.1.0 LANGUAGES C)

add_executable(
    ${PROJECT_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mdns.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mdns_types.c
)

target_include_directories(
    ${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

IF (WIN32)
target_link_libraries(yiikplay_test ws2_32)
ENDIF()