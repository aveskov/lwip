cmake_minimum_required(VERSION 3.10)
project(lwipdll C CXX)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)  # Back to C++14 since we're not using problematic headers
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the source root
set(LWIP_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(LWIP_INCLUDE ${LWIP_SRC}/include)

# BoringSSL
set(BORINGSSL_ROOT "${CMAKE_SOURCE_DIR}/../boringssl")
set(BORINGSSL_INCLUDE "${BORINGSSL_ROOT}/include")

# Check if BoringSSL libraries exist
if(EXISTS "${BORINGSSL_ROOT}/build/ssl/ssl.lib")
    set(BORINGSSL_LIB "${BORINGSSL_ROOT}/build/ssl/ssl.lib")
    set(CRYPTO_LIB "${BORINGSSL_ROOT}/build/crypto/crypto.lib")
elseif(EXISTS "${BORINGSSL_ROOT}/build/ssl.lib")
    set(BORINGSSL_LIB "${BORINGSSL_ROOT}/build/ssl.lib")
    set(CRYPTO_LIB "${BORINGSSL_ROOT}/build/crypto.lib")
else()
    message(FATAL_ERROR "BoringSSL libraries not found in ${BORINGSSL_ROOT}/build")
endif()

# Collect LwIP core source files (C only)
file(GLOB_RECURSE LWIP_CORE_SOURCES
    ${LWIP_SRC}/core/*.c
    ${LWIP_SRC}/core/ipv4/*.c
    ${LWIP_SRC}/api/*.c
    ${LWIP_SRC}/netif/*.c
)

# Wrapper source files
set(WRAPPER_C_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/wrapper/lwip_wrapper.c
)

# SSL wrapper (compile as C++)
set(WRAPPER_CXX_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/wrapper/lwip_wrapper_ssl.cpp
)

# Port files
set(PORT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/port/sys_arch.c
)

# Create the shared library (DLL)
add_library(lwip SHARED 
    ${LWIP_CORE_SOURCES}
    ${WRAPPER_C_SOURCES}
    ${WRAPPER_CXX_SOURCES}
    ${PORT_SOURCES}
)

# Set compile properties for SSL wrapper
set_source_files_properties(${WRAPPER_CXX_SOURCES} PROPERTIES LANGUAGE CXX)

# Link libraries
target_link_libraries(lwip PRIVATE
    ${BORINGSSL_LIB}
    ${CRYPTO_LIB}
    ws2_32
    iphlpapi
    crypt32
)

# Include directories
target_include_directories(lwip PUBLIC
    ${LWIP_INCLUDE}
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${CMAKE_CURRENT_SOURCE_DIR}/port    
    ${CMAKE_CURRENT_SOURCE_DIR}/wrapper
)

# Preprocessor definitions
target_compile_definitions(lwip PRIVATE
    LWIP_DLL_EXPORTS
    NO_SYS=1
    LWIP_RAW=1
    LWIP_IPV4=1
    LWIP_TCP=1
    LWIP_ETHERNET=1
    LWIP_ARP=1
    MEM_LIBC_MALLOC=1
    MEMP_MEM_MALLOC=1
    LWIP_TIMEVAL_PRIVATE=0
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

# MSVC specific settings
if(MSVC)
    target_compile_options(lwip PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/std:c++14>
        $<$<COMPILE_LANGUAGE:CXX>:/EHsc>
        /W3
        /wd4996
        /wd4244
        /wd4267
    )
endif()