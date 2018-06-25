cmake_minimum_required(VERSION 3.10)
project(CryptPy)

set(CMAKE_CXX_STANDARD 11)
execute_process(COMMAND echo -n /home/srinag/.local/lib/python3.6/site-packages OUTPUT_VARIABLE libdest)
add_library(CryptPy SHARED CryptPy.cpp)
target_link_libraries(CryptPy Crypt boost_python3)
include_directories(/usr/include/python3.6m)
INSTALL(TARGETS CryptPy
        LIBRARY DESTINATION ${libdest})
