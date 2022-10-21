cmake_minimum_required(VERSION 3.15.3)
project(crypto_test C)

MESSAGE(STATUS "operation system is ${CMAKE_SYSTEM}")

set(CMAKE_C_STANDARD 99)

# Set the host paths
SET(MAIN_DIR ./)
SET(LIB_DIR_KASUMI lib/kasumi)
SET(MODULE_ASYM_DIR modules/asym)
SET(MODULE_CERT_DIR modules/cert)
SET(MODULE_COMMON_DIR modules/common)
SET(MODULE_DIGEST_DIR modules/digest)
SET(MODULE_RANDOM_DIR modules/random)
SET(MODULE_SYM_DIR modules/sym)
SET(UTILS_DIR utils)
SET(TEST_SUITE_DIR testsuite)

# Set SRC
SET(SRC_LIB_KASUMI ${LIB_DIR_KASUMI})
SET(SRC_MODULE_ASYM ${MODULE_ASYM_DIR}/src)
SET(SRC_MODULE_CERT ${MODULE_CERT_DIR}/src)
SET(SRC_MODULE_COMMON ${MODULE_COMMON_DIR}/src)
SET(SRC_MODULE_DIGEST ${MODULE_DIGEST_DIR}/src)
SET(SRC_MODULE_RANDOM ${MODULE_RANDOM_DIR}/src)
SET(SRC_MODULE_SYM ${MODULE_SYM_DIR}/src)
SET(SRC_TEST_SUITE ${TEST_SUITE_DIR}/src ${TEST_SUITE_DIR}/thirdpart/src)
SET(SRC_UTILS ${UTILS_DIR}/src)
SET(SRC_MAIN ${TEST_SUITE_DIR})

file(GLOB_RECURSE SRC_LIB_KASUMI "${SRC_LIB_KASUMI}/*.c")
file(GLOB_RECURSE SRC_MODULE_ASYM "${SRC_MODULE_ASYM}/*.c")
file(GLOB_RECURSE SRC_MODULE_CERT "${SRC_MODULE_CERT}/*.c")
file(GLOB_RECURSE SRC_MODULE_COMMON "${SRC_MODULE_COMMON}/*.c")
file(GLOB_RECURSE SRC_MODULE_DIGEST "${SRC_MODULE_DIGEST}/*.c")
file(GLOB_RECURSE SRC_MODULE_RANDOM "${SRC_MODULE_RANDOM}/*.c")
file(GLOB_RECURSE SRC_MODULE_SYM "${SRC_MODULE_SYM}/*.c")
file(GLOB_RECURSE SRC_TEST_SUITE "${SRC_TEST_SUITE}/*.c")
file(GLOB_RECURSE SRC_UTILS "${SRC_UTILS}/*.c")
file(GLOB_RECURSE SRC_MAIN "${SRC_MAIN}/*.c")

SET(SRC_ALL ${SRC_LIB_KASUMI}
            ${SRC_MODULE_ASYM}
            ${SRC_MODULE_CERT}
            ${SRC_MODULE_COMMON}
            ${SRC_MODULE_DIGEST}
            ${SRC_MODULE_RANDOM}
            ${SRC_MODULE_SYM}
            ${SRC_TEST_SUITE}
            ${SRC_UTILS}
            ${SRC_MAIN})

# Set INCLUDE
SET(INC_LIB_KASUMI ${LIB_DIR_KASUMI})
SET(INC_MODULE_ASYM ${MODULE_ASYM_DIR}/inc)
SET(INC_MODULE_CERT ${MODULE_CERT_DIR}/inc)
SET(INC_MODULE_COMMON ${MODULE_COMMON_DIR}/inc)
SET(INC_MODULE_DIGEST ${MODULE_DIGEST_DIR}/inc)
SET(INC_MODULE_RANDOM ${MODULE_RANDOM_DIR}/inc)
SET(INC_MODULE_SYM ${MODULE_SYM_DIR}/inc)
SET(INC_TEST_SUITE ${TEST_SUITE_DIR}/inc ${TEST_SUITE_DIR}/thirdpart/inc)
SET(INC_UTILS ${UTILS_DIR}/inc)
SET(INC_MAIN ${MAIN_DIR})

include_directories(
        ${INC_LIB_KASUMI}
        ${INC_MODULE_ASYM}
        ${INC_MODULE_CERT}
        ${INC_MODULE_COMMON}
        ${INC_MODULE_DIGEST}
        ${INC_MODULE_RANDOM}
        ${INC_MODULE_SYM}
        ${INC_TEST_SUITE}
        ${INC_UTILS}
        ${INC_MAIN})


# set library
IF(WIN32)
        MESSAGE(STATUS "Now is windows")
        SET(LIB_OPENSSL_STATIC_PATH C:/Program\ Files/OpenSSL-Win64)
        SET(LIB_MBEDTLS_STATIC_PATH C:/opt/mbedtls-2.16.5)
        include_directories(
            ${LIB_OPENSSL_STATIC_PATH}/include
            ${LIB_MBEDTLS_STATIC_PATH}/include)
        link_libraries(
            ${LIB_OPENSSL_STATIC_PATH}/lib/libssl.lib
            ${LIB_OPENSSL_STATIC_PATH}/lib/libcrypto.lib
            ${LIB_MBEDTLS_STATIC_PATH}/library/libmbedtls.a
            ${LIB_MBEDTLS_STATIC_PATH}/library/libmbedcrypto.a
            ${LIB_MBEDTLS_STATIC_PATH}/library/libmbedx509.a
            -lws2_32)
ELSEIF(APPLE)
        MESSAGE(STATUS "Now is apple")
        SET(LIB_OPENSSL_STATIC_PATH /usr/local/openssl)
        SET(LIB_MBEDTLS_STATIC_PATH /usr/local)
        SET(LIB_GMSSL_STATIC_PATH /Users/carlos/workspace/work/GmSSL)
        include_directories(    ${LIB_OPENSSL_STATIC_PATH}/include/openssl
                                ${LIB_MBEDTLS_STATIC_PATH}/include/mbedtls
                                ${LIB_MBEDTLS_STATIC_PATH}/include)
        include_directories(${LIB_OPENSSL_STATIC_PATH}/lib ${LIB_MBEDTLS_STATIC_PATH}/lib)
        link_libraries(
            #${LIB_OPENSSL_STATIC_PATH}/lib/libssl.a
            #${LIB_OPENSSL_STATIC_PATH}/lib/libcrypto.a
            ${LIB_GMSSL_STATIC_PATH}/libssl.a
            ${LIB_GMSSL_STATIC_PATH}/libcrypto.a
            ${LIB_MBEDTLS_STATIC_PATH}/lib/libmbedtls.a
            ${LIB_MBEDTLS_STATIC_PATH}/lib/libmbedx509.a
            ${LIB_MBEDTLS_STATIC_PATH}/lib/libmbedcrypto.a)

ELSEIF(UNIX)
    MESSAGE(STATUS "Now is Linux")
    SET(openssl_dir /usr/local/openssl)
    SET(mbedtls_dir /usr/local/mbedtls)
    SET(SRC_PATH ${DIR_SRCS}
            src/testsuite/thirdpart/Sources/Basic.c
            src/testsuite/thirdpart/Sources/CUError.c
            src/testsuite/thirdpart/Sources/MyMem.c
            src/testsuite/thirdpart/Sources/TestDB.c
            src/testsuite/thirdpart/Sources/TestRun.c
            src/testsuite/thirdpart/Sources/Util.c
            srcs/testsuite/test_main.c src/testsuite/test_main.h
            src/testsuite/ExampleTests.c
            src/testsuite/OpensslTests.c
            src/kasumi/f8.c src/kasumi/kasumi.h src/kasumi/f9.c
            src/kasumi/kasumi.c src/kasumi/test_kasumi.c src/kasumi/test_kasumi.h
            #src/mbedtls_cmac_exa.c inc/mbedtls_cmac_exa.h
            src/aes.h src/test_data_aes_cbc.h)
    include_directories(${openssl_dir}/include ${mbedtls_dir}/include ./inc)
    include_directories(${openssl_dir}/lib ${mbedtls_dir}/library)
    include_directories(${cunit_dir}/Headers)
    link_libraries(
            ${openssl_dir}/lib/libssl.so
            ${openssl_dir}/lib/libcrypto.so
            ${mbedtls_dir}/lib/libmbedtls.so
            ${mbedtls_dir}/lib/libmbedx509.so
            ${mbedtls_dir}/lib/libmbedcrypto.so)
ENDIF()

add_executable("${PROJECT_NAME}_entry.elf" ${SRC_ALL})