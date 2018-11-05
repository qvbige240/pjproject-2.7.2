#!/bin/bash
# COMPILE-compiler
# android
set -e

# source code
export pjsip_SRC=`pwd`

##### android ##### 
export SCRIPT_PATH=`pwd`/script
export INSTALL_PATH=`pwd`/final_android
export RELEASE_PATH=`pwd`/release
export BUILD_ROOT_PATH=`pwd`/build_android
export FINAL_PATH=$INSTALL_PATH
export BUILD_PATH=$BUILD_ROOT_PATH

rm -rf $BUILD_PATH
mkdir -p $BUILD_PATH
if [ ! -d ${FINAL_PATH} ]; then
    mkdir ${FINAL_PATH}
fi

if true;then
# Build Environment
NDK_PATH=${NDK_HOME}        # /home/zouqing/android/android-ndk-r10b
BUILD_PLATFORM=linux-x86_64
TOOLCHAIN_VERSION=4.8       # 4.8
ANDROID_VERSION=19

# 32-bit arm build
HOST=arm-linux-androideabi
#HOST=i686-linux-android 
#export TARGETMACH=x86
export TARGETMACH=arm-linux-androideabi
SYSROOT=${NDK_PATH}/platforms/android-${ANDROID_VERSION}/arch-arm
ANDROID_CFLAGS="--sysroot=${SYSROOT}"

TOOLCHAIN=${NDK_PATH}/toolchains/${TARGETMACH}-${TOOLCHAIN_VERSION}/prebuilt/${BUILD_PLATFORM}
ANDROID_INCLUDES="-I${SYSROOT}/usr/include -I${TOOLCHAIN}/include"
#export CPP=${TOOLCHAIN}/bin/${HOST}-cpp
#export CXX=${TOOLCHAIN}/bin/${HOST}-g++
#export AR=${TOOLCHAIN}/bin/${HOST}-ar
#export AS=${TOOLCHAIN}/bin/${HOST}-as
#export NM=${TOOLCHAIN}/bin/${HOST}-nm
#export CC=${TOOLCHAIN}/bin/${HOST}-gcc
#export LD=${TOOLCHAIN}/bin/${HOST}-ld
#export RANLIB=${TOOLCHAIN}/bin/${HOST}-ranlib
#export OBJDUMP=${TOOLCHAIN}/bin/${HOST}-objdump
#export STRIP=${TOOLCHAIN}/bin/${HOST}-strip

else
#export CC=gcc
#export CXX=g++

HOST=arm-linux-androideabi
fi


if true;then
    export ANDROID_NDK_ROOT=${NDK_HOME}
    export APP_PLATFORM=android-9
    export TARGET_ABI=armeabi
    function build_pjsip()
    {
        echo "#####################    Build pjsip   #####################"
        echo "   "
        #cd ${BUILD_PATH}
        #rm -rf *
        cd ${pjsip_SRC}   # compile directly
        if [ -f ${pjsip_SRC}/build.mak ]; then
            make clean
        fi
        sed -i "/^#define PJ_CONFIG_ANDROID.*/s/_[A-Z].*/_CONFIG_ANDROID 1/" ${pjsip_SRC}/pjlib/include/pj/config_site.h
        ${pjsip_SRC}/configure-android --prefix=${FINAL_PATH} 
#    	    CFLAGS="-g -DPJMEDIA_AUDIO_DEV_HAS_NULL_AUDIO"
        make dep
        make clean
        make
        make install
    }
else
    function build_pjsip()
    {
        echo "#####################    Build pjsip   #####################"
        echo "   "
        #cd ${BUILD_PATH}
        #rm -rf *
        cd ${pjsip_SRC}   # compile directly
        if [ -f ${pjsip_SRC}/build.mak ]; then
            make clean
        fi
        sed -i "/^#define PJ_CONFIG_ANDROID.*/s/_[A-Z].*/_CONFIG_ANDROID 1/" ${pjsip_SRC}/pjlib/include/pj/config_site.h
        ${pjsip_SRC}/aconfigure --prefix=${FINAL_PATH} --host=${TARGETMACH} \
	        CFLAGS="-g -O0 -DPJMEDIA_AUDIO_DEV_HAS_NULL_AUDIO ${ANDROID_INCLUDES} ${ANDROID_CFLAGS}" \
	        CPPFLAGS="${ANDROID_INCLUDES} ${ANDROID_CFLAGS} -fexceptions -frtti" \
	        CPPFLAGS="${ANDROID_INCLUDES} -shared ${ANDROID_CFLAGS} -fexceptions -frtti" \
	        LDFLAGS="${ANDROID_CFLAGS} "
        make dep
        make clean
        make
        make install
    }
fi


#build_libjpeg_turbo
build_pjsip

