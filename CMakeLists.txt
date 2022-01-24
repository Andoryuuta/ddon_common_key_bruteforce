cmake_minimum_required(VERSION 3.8)

set(DDON_BRUTEFORCE_EXE ddon_common_key_bruteforce)
set(DDON_ENABLE_SIMD 1)

if (DDON_ENABLE_SIMD)
    message("SIMD enabled")
endif ()

project(${DDON_BRUTEFORCE_EXE})

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if (CMAKE_CXX_COMPILER_FRONTEND_VARIANT STREQUAL "MSVC")
        message(FATAL_ERROR "Cannot be compiled clang-cl due to https://github.com/p-ranav/argparse/issues/136.")
    endif ()
endif ()


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Set MSVC optimization flags
if (MSVC)
    set(CMAKE_CXX_FLAGS "/O2 /Oi /Ot /Oy /EHsc")
endif ()

set(DDON_BRUTEFORCE_EXE_SOURCES
        src/seeded_xorshift_128.hpp
        src/ctpl_stl.h
        src/camellia.h
        src/camellia.c
        src/argparse.hpp
        src/main.cpp
        src/simd_brute_force.h
        )

add_executable(${DDON_BRUTEFORCE_EXE} ${DDON_BRUTEFORCE_EXE_SOURCES})


if (DDON_ENABLE_SIMD)
    target_compile_definitions(${DDON_BRUTEFORCE_EXE} PUBLIC DDON_SIMD_ENABLED)
    # camellia_simd
    set(CAMELLIA_SIMD camellia_simd_lib)
    set(CAMELLIA_SIMD_SOURCES
            #camellia-simd-aesni/camellia_simd.h
            camellia-simd-aesni/camellia_simd128_with_aes_instruction_set.c
            #camellia-simd-aesni/camellia_simd256_x86_aesni.c
            #camellia-simd-aesni/camellia_simd128_x86-64_aesni_avx.S
            #camellia-simd-aesni/camellia_simd256_x86-64_aesni_avx2.S
            )
    add_library(${CAMELLIA_SIMD} STATIC ${CAMELLIA_SIMD_SOURCES})
    target_include_directories(${CAMELLIA_SIMD} PUBLIC camellia-simd-aesni/)
    target_compile_options(${CAMELLIA_SIMD} PUBLIC
            -maes
            -mavx2
            #-msse4.1
            -mtune=native
            -march=sandybridge
            )
    #target_link_options(${CAMELLIA_SIMD} PUBLIC
    #        LINKER:-lcrypto
    #        )
    target_link_libraries(${DDON_BRUTEFORCE_EXE} PUBLIC ${CAMELLIA_SIMD})
endif ()