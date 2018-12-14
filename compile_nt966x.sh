#!/bin/bash
# COMPILE-compiler
# mips-nt966x
set -e

# source code, libxxx_SRC define  such as libupnp_SRC
export pjsip_SRC=`pwd`

##### pc ##### 
export SCRIPT_PATH=`pwd`/script
export INSTALL_PATH=`pwd`/final_nt966x
export RELEASE_PATH=`pwd`/release
export BUILD_ROOT_PATH=`pwd`/build_nt966x
export FINAL_PATH=$INSTALL_PATH
export BUILD_PATH=$BUILD_ROOT_PATH

rm -rf $BUILD_PATH
mkdir -p $BUILD_PATH
if [ -d ${FINAL_PATH} ]; then
    rm -rf ${FINAL_PATH}
fi
mkdir ${FINAL_PATH}

if true; then
    export INSTALLDIR=/opt/mipsel-24kec-linux-uclibc/usr
    #export PATH=$INSTALLDIR/bin:$PATH
    export PATH=$PATH:$INSTALLDIR/bin
    export TARGETMACH=mipsel-24kec-linux-uclibc
    export BUILDMACH=i686-pc-linux-gnu
    #export BUILDMACH=x86_64-unknown-linux-gnu
    export CROSS=mipsel-24kec-linux-uclibc
    export CC=${CROSS}-gcc
    # ld is set to gcc when pjproject compile
    #export LD=${CROSS}-ld
    export AS=${CROSS}-as
    export CXX=${CROSS}-g++
fi

GBASE_SYSROOT="/opt/mipsel-24kec-linux-uclibc/usr/mipsel-24kec-linux-uclibc/sysroot"
GBASE_INCLUDE="/opt/mipsel-24kec-linux-uclibc/usr/mipsel-24kec-linux-uclibc/sysroot/usr/include"
GBASE_LIB="/opt/mipsel-24kec-linux-uclibc/usr/mipsel-24kec-linux-uclibc/sysroot/lib"
GOLBAL_CFLAGS="-DDEBUG -I${GBASE_INCLUDE}"
GOLBAL_CPPFLAGS="-DDEBUG -I${GBASE_INCLUDE}"
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
    ${pjsip_SRC}/aconfigure --prefix=${FINAL_PATH} --host=$TARGETMACH \
        --disable-libwebrtc --enable-shared \
        CFLAGS="-DPJMEDIA_AUDIO_DEV_HAS_NULL_AUDIO $GOLBAL_CFLAGS -I${FINAL_PATH}/include" \
        CPPFLAGS="$GOLBAL_CPPFLAGS -I${FINAL_PATH}/include" \
        LDFLAGS="$GOLBAL_LDFLAGS -L${FINAL_PATH}/lib"
    make dep
    #make clean
    make
    make install
}


build_pjsip


