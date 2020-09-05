cmake_minimum_required(VERSION 3.17)
project(warm_openssl C)

set(CMAKE_C_STANDARD 99)

link_directories(/usr/local/openssl/lib /usr/local/lib)
include_directories(/usr/local/openssl/include /usr/local/include)
link_libraries(mbedx509 mbedtls mbedcrypto ssl crypto)

add_executable(warm_openssl main.c openssl_rsa.c openssl_sm2.c test_case.c openssl_rsa.h openssl_sm2.h test_case.h openssl_md_sha.c openssl_md_sha.h mbedtls_md_sha.c mbedtls_md_sha.h)