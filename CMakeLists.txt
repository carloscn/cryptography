cmake_minimum_required(VERSION 3.17)
project(carlos_openmbed C)

MESSAGE(STATUS "operation system is ${CMAKE_SYSTEM}")

set(CMAKE_C_STANDARD 99)
AUX_SOURCE_DIRECTORY(src DIR_SRCS)
SET(SRC_PATH ${DIR_SRCS} src/openssl_ecc.c inc/openssl_ecc.h)
IF(WIN32)
    SET(openssl_dir C:/Program\ Files/OpenSSL-Win64)
    SET(mbedtls_dir C:/opt/mbedtls-2.16.5)
    MESSAGE(STATUS "Now is windows")
    include_directories(${openssl_dir}/include ${mbedtls_dir}/include ./inc)
    include_directories(${openssl_dir}/lib ${mbedtls_dir}/library)
    link_libraries(${openssl_dir}/lib/libssl.lib
            ${openssl_dir}/lib/libcrypto.lib
            ${mbedtls_dir}/library/libmbedtls.a
            ${mbedtls_dir}/library/libmbedcrypto.a)
    add_executable(${PROJECT_NAME} ${SRC_PATH})
ELSEIF(APPLE)
    SET(openssl_dir /usr/local/openssl)
    SET(mbedtls_dir /usr/local/include)
    MESSAGE(STATUS "Now is apple")
    include_directories(${openssl_dir}/include ${mbedtls_dir}/include ./inc)
    include_directories(${openssl_dir}/lib ${mbedtls_dir}/library)
    link_libraries(ssl libcrypto mbedtls mbedcrypto)
    add_executable(${PROJECT_NAME} ${SRC_PATH})
ENDIF()




