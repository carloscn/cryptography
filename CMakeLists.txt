cmake_minimum_required(VERSION 3.15.3)
project(carlos_openmbed C)

MESSAGE(STATUS "operation system is ${CMAKE_SYSTEM}")

set(CMAKE_C_STANDARD 99)
AUX_SOURCE_DIRECTORY(src DIR_SRCS)
SET(cunit_dir ./src/testsuite/thirdpart)
SET(SRC_PATH ${DIR_SRCS} src/openssl_ecc.c inc/openssl_ecc.h
        src/mbedtls_rsa.c inc/mbedtls_rsa.h
        inc/openssl_cfg.h inc/mbedtls_cfg.h
        src/mbedtls_ecc.c inc/mbedtls_ecc.h
        inc/errors.h inc/cfg.h src/openssl_common.c inc/openssl_common.h
        inc/mbedtls_common.h src/mbedtls_common.c
        src/mbedtls_random.c inc/mbedtls_random.h
        src/utils_net_server.c inc/utils_net_client.h
        inc/utils_net_sever.h src/utils_net_client.c
        src/mbedtls_dh_server.c inc/mbedtls_dh_server.h
        src/mbedtls_dh_client.c inc/mbedtls_dh_client.h
        src/mbedtls_gen_dh.c inc/mbedtls_gen_dh.h
        inc/mbedtls_ecdh_client.h inc/mbedtls_ecdh_server.h
        src/mbedtls_ecdh_client.c src/mbedtls_ecdh_server.c
        src/openssl_dh_client.c src/openssl_dh_server.c
        inc/openssl_dh_client.h inc/openssl_dh_server.h
        src/openssl_gen_dh.c inc/openssl_gen_dh.h
        src/mbedtls_cert_csr.c inc/mbedtls_cert_csr.h
        src/mbedtls_cert_crt.c inc/mbedtls_cert_crt.h
        src/mbedtls_sca.c inc/mbedtls_sca.h
        src/openssl_sca.c inc/openssl_sca.h
        src/unit_test_mbedtls.c
        )
IF(WIN32)
    SET(openssl_dir C:/Program\ Files/OpenSSL-Win64)
    SET(mbedtls_dir C:/opt/mbedtls-2.16.5)
    MESSAGE(STATUS "Now is windows")
    include_directories(${openssl_dir}/include
            ${mbedtls_dir}/include
            ./inc
            src/testsuite/thirdpart/Headers
            src/testsuite
            src/testsuite/thirdpart/Sources)
    SET(SRC_PATH ${DIR_SRCS}
            src/testsuite/thirdpart/Sources/Basic.c
            src/testsuite/thirdpart/Sources/CUError.c
            src/testsuite/thirdpart/Sources/MyMem.c
            src/testsuite/thirdpart/Sources/TestDB.c
            src/testsuite/thirdpart/Sources/TestRun.c
            src/testsuite/thirdpart/Sources/Util.c
            src/testsuite/test_main.c src/testsuite/test_main.h
            src/testsuite/ExampleTests.c
            src/testsuite/OpensslTests.c
            src/kasumi/f8.c src/kasumi/kasumi.h src/kasumi/f9.c
            src/kasumi/kasumi.c src/kasumi/test_kasumi.c src/kasumi/test_kasumi.h
            src/mbedtls_cmac_exa.c inc/mbedtls_cmac_exa.h)
    include_directories(${openssl_dir}/lib ${mbedtls_dir}/library ${cunit_dir}/Headers)
    link_libraries(
            ${openssl_dir}/lib/libssl.lib
            ${openssl_dir}/lib/libcrypto.lib
            ${mbedtls_dir}/library/libmbedtls.a
            ${mbedtls_dir}/library/libmbedcrypto.a
            ${mbedtls_dir}/library/libmbedx509.a
            -lws2_32
    )
    add_executable(${PROJECT_NAME} ${SRC_PATH})

ELSEIF(APPLE)
    SET(openssl_dir /usr/local/openssl)
    SET(mbedtls_dir /usr/local/include)
    MESSAGE(STATUS "Now is apple")
    include_directories(${openssl_dir}/include ${mbedtls_dir}/../include ./inc)
    include_directories(${openssl_dir}/lib ${mbedtls_dir}/../library)
    #link_libraries(ssl libcrypto mbedtls mbedcrypto)
    link_libraries(
            ${openssl_dir}/lib/libssl.a
            ${openssl_dir}/lib/libcrypto.a
            ${mbedtls_dir}/../lib/libmbedtls.a
            ${mbedtls_dir}/../lib/libmbedx509.a
            ${mbedtls_dir}/../lib/libmbedcrypto.a)
    add_executable(${PROJECT_NAME} ${SRC_PATH})

ELSEIF(UNIX)
    SET(openssl_dir /usr/local/openssl)
    SET(mbedtls_dir /usr/local/mbedtls)
    MESSAGE(STATUS "Now is Linux")
    include_directories(${openssl_dir}/include ${mbedtls_dir}/include ./inc)
    include_directories(${openssl_dir}/lib ${mbedtls_dir}/library)
    link_libraries(
            ${openssl_dir}/lib/libssl.so
            ${openssl_dir}/lib/libcrypto.so
            ${mbedtls_dir}/lib/libmbedtls.so
            ${mbedtls_dir}/lib/libmbedx509.so
            ${mbedtls_dir}/lib/libmbedcrypto.so)
    add_executable(${PROJECT_NAME} ${SRC_PATH})
ENDIF()




