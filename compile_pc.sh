#!/bin/bash
# COMPILE-compiler
# pc-x86
set -e

# source code, libxxx_SRC define  such as libupnp_SRC
export pjsip_SRC=`pwd`

##### pc ##### 
export SCRIPT_PATH=`pwd`/script
export INSTALL_PATH=`pwd`/final_x86
export RELEASE_PATH=`pwd`/release
export BUILD_ROOT_PATH=`pwd`/build_x86
export FINAL_PATH=$INSTALL_PATH
export BUILD_PATH=$BUILD_ROOT_PATH

rm -rf $BUILD_PATH
mkdir -p $BUILD_PATH
if [ ! -d ${FINAL_PATH} ]; then
    mkdir ${FINAL_PATH}
fi

if false;then
# Build Environment
export INSTALLDIR=/opt/timesys/toolchains/i686-linux
export PATH=$INSTALLDIR/bin:$PATH
export TARGETMACH=i686-linux
export BUILDMACH=i686-pc-linux-gnu
export CROSS=i686-linux
export CC=${CROSS}-gcc
export LD=${CROSS}-ld
export AS=${CROSS}-as
export CXX=${CROSS}-g++
else
export CC=gcc
export CXX=g++
fi

GBASE_INCLUDE="/usr/include"
GBASE_LIB="/usr/lib"
GOLBAL_CFLAGS="-I${GBASE_INCLUDE}"
GOLBAL_CPPFLAGS="-I${GBASE_INCLUDE}"
GOLBAL_LDFLAGS="-L${GBASE_LIB}"


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
    sed -i "/^#define PJ_CONFIG_ANDROID.*/s/_[A-Z].*/_CONFIG_ANDROID 0/" ${pjsip_SRC}/pjlib/include/pj/config_site.h
    ${pjsip_SRC}/aconfigure --prefix=${FINAL_PATH} --enable-shared \
        CFLAGS="-g -O0 -DPJMEDIA_AUDIO_DEV_HAS_NULL_AUDIO $GOLBAL_CFLAGS -I${FINAL_PATH}/include" \
        CPPFLAGS="$GOLBAL_CPPFLAGS -I${FINAL_PATH}/include"
    make dep
    make clean
    make
    make install
}

build_pjsip


