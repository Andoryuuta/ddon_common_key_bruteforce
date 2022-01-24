cmake_minimum_required(VERSION 3.8)

set(DDON_BRUTEFORCE_EXE ddon_common_key_bruteforce)
set(DDON_ENABLE_SIMD 0)
set(DDON_ENABLE_ASM 0)

if (DDON_ENABLE_SIMD)
    message("SIMD enabled")
endif ()
if (DDON_ENABLE_ASM)
    message("ASM enabled")
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

message(Project: ${PROJECT_NAME})
message(BuildType: ${CMAKE_BUILD_TYPE})
message(CMAKE_CXX_COMPILER_ID: ${CMAKE_CXX_COMPILER_ID})
message(CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME})

IF (CMAKE_BUILD_TYPE MATCHES Debug)
    set(DDON_DEBUG TRUE)
ENDIF()

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
        src/depth_brute_force.h
        src/ddon_random.hpp
        )

add_executable(${DDON_BRUTEFORCE_EXE} ${DDON_BRUTEFORCE_EXE_SOURCES})


if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    IF (DDON_DEBUG)
        message([LOWL] Setting Debug Flags)
        target_compile_options(${DDON_BRUTEFORCE_EXE} PRIVATE
                -O0
                -Werror
                )
    ELSE()
        message([LOWL] Setting Release Flags)
        target_compile_options(${DDON_BRUTEFORCE_EXE} PRIVATE
                -O2
                -Werror
                )
    ENDIF ()
endif ()

if (DDON_ENABLE_SIMD)
    # camellia_simd
    target_compile_definitions(${DDON_BRUTEFORCE_EXE} PUBLIC DDON_SIMD_ENABLED)
    set(CAMELLIA_SIMD camellia_simd_lib)

    if (DDON_ENABLE_ASM)
        enable_language(ASM)
        set(CAMELLIA_SIMD_SOURCES
                camellia-simd-aesni/camellia_simd128_x86-64_aesni_avx.S
                )
    else ()
        set(CAMELLIA_SIMD_SOURCES
                camellia-simd-aesni/camellia_simd128_with_aes_instruction_set.c
                )
    endif ()


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