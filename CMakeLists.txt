cmake_minimum_required(VERSION 3.10)
project(CloudIPFilter VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src)

find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(CloudIPFilter
    src/main.cpp
    src/filter.cpp
    src/utils.cpp
)

target_link_libraries(CloudIPFilter PRIVATE CURL::libcurl nlohmann_json::nlohmann_json)

install(TARGETS CloudIPFilter DESTINATION bin)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    target_link_libraries(CloudIPFilter stdc++fs)
endif()
