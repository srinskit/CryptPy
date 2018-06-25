cmake_minimum_required(VERSION 3.10)
project(CryptPy)

set(CMAKE_CXX_STANDARD 11)
execute_process(COMMAND python3 -m site --user-site OUTPUT_VARIABLE libdest)
add_library(CryptPy SHARED CryptPy.cpp)
include_directories(/usr/include/python3.6m)
target_link_libraries(CryptPy Crypt)
INSTALL(TARGETS CryptPy
        LIBRARY DESTINATION ${libdest}
        )
