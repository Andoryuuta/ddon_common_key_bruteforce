cmake_minimum_required (VERSION 3.8)
project("ddon_common_key_bruteforce")


if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if (CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
    message(FATAL_ERROR "Cannot be compiled clang-cl due to https://github.com/p-ranav/argparse/issues/136." )
  endif()
endif()


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Set MSVC optimization flags
if(MSVC)
	set(CMAKE_CXX_FLAGS "/O2 /Oi /Ot /Oy /EHsc")
endif()

add_executable(ddon_common_key_bruteforce
	src/seeded_xorshift_128.hpp
	src/ctpl_stl.h
	src/camellia.h
	src/camellia.c
	src/argparse.hpp
	src/main.cpp
)