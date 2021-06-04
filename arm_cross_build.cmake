SET(CROSS_COMPILE 1)

IF(CROSS_COMPILE)

    SET(CMAKE_SYSTEM_NAME Linux)
    SET(TOOLCHAIN_DIR "/opt/cross-arm/linaro64")

    set(CMAKE_CXX_COMPILER ${TOOLCHAIN_DIR}/bin/aarch64-linux-gnu-g++)
    set(CMAKE_C_COMPILER   ${TOOLCHAIN_DIR}/bin/aarch64-linux-gnu-gcc)
    #set(GNU_FLAGS "-mfpu=vfp -fPIC")
    set(CMAKE_CXX_FLAGS "${GNU_FLAGS} ")
    set(CMAKE_C_FLAGS "${GNU_FLAGS}  ")


    SET(CMAKE_FIND_ROOT_PATH  ${TOOLCHAIN_DIR}
            ${TOOLCHAIN_DIR}/include
            ${TOOLCHAIN_DIR}/lib )

    #link_directories(/home/zchx/Downloads/live_arm/UsageEnvironment/)

ENDIF(CROSS_COMPILE)
