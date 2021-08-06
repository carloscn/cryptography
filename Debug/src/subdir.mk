################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/main.c \
../src/mbedtls_cert_crt.c \
../src/mbedtls_cert_csr.c \
../src/mbedtls_common.c \
../src/mbedtls_dh_client.c \
../src/mbedtls_dh_server.c \
../src/mbedtls_ecc.c \
../src/mbedtls_ecdh_client.c \
../src/mbedtls_ecdh_server.c \
../src/mbedtls_gen_dh.c \
../src/mbedtls_md_sha.c \
../src/mbedtls_random.c \
../src/mbedtls_rsa.c \
../src/mbedtls_sca.c \
../src/openssl_common.c \
../src/openssl_dh_client.c \
../src/openssl_dh_server.c \
../src/openssl_ecc.c \
../src/openssl_gen_dh.c \
../src/openssl_md_sha.c \
../src/openssl_rsa.c \
../src/openssl_sca.c \
../src/openssl_sm2.c \
../src/unit_test.c \
../src/utils.c \
../src/utils_net_client.c \
../src/utils_net_server.c 

OBJS += \
./src/main.o \
./src/mbedtls_cert_crt.o \
./src/mbedtls_cert_csr.o \
./src/mbedtls_common.o \
./src/mbedtls_dh_client.o \
./src/mbedtls_dh_server.o \
./src/mbedtls_ecc.o \
./src/mbedtls_ecdh_client.o \
./src/mbedtls_ecdh_server.o \
./src/mbedtls_gen_dh.o \
./src/mbedtls_md_sha.o \
./src/mbedtls_random.o \
./src/mbedtls_rsa.o \
./src/mbedtls_sca.o \
./src/openssl_common.o \
./src/openssl_dh_client.o \
./src/openssl_dh_server.o \
./src/openssl_ecc.o \
./src/openssl_gen_dh.o \
./src/openssl_md_sha.o \
./src/openssl_rsa.o \
./src/openssl_sca.o \
./src/openssl_sm2.o \
./src/unit_test.o \
./src/utils.o \
./src/utils_net_client.o \
./src/utils_net_server.o 

C_DEPS += \
./src/main.d \
./src/mbedtls_cert_crt.d \
./src/mbedtls_cert_csr.d \
./src/mbedtls_common.d \
./src/mbedtls_dh_client.d \
./src/mbedtls_dh_server.d \
./src/mbedtls_ecc.d \
./src/mbedtls_ecdh_client.d \
./src/mbedtls_ecdh_server.d \
./src/mbedtls_gen_dh.d \
./src/mbedtls_md_sha.d \
./src/mbedtls_random.d \
./src/mbedtls_rsa.d \
./src/mbedtls_sca.d \
./src/openssl_common.d \
./src/openssl_dh_client.d \
./src/openssl_dh_server.d \
./src/openssl_ecc.d \
./src/openssl_gen_dh.d \
./src/openssl_md_sha.d \
./src/openssl_rsa.d \
./src/openssl_sca.d \
./src/openssl_sm2.d \
./src/unit_test.d \
./src/utils.d \
./src/utils_net_client.d \
./src/utils_net_server.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


