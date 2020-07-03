# build/os-auto.mak.  Generated from os-auto.mak.in by configure.

export OS_CFLAGS   := $(CC_DEF)PJ_AUTOCONF=1 -g -O0 -DPJMEDIA_AUDIO_DEV_HAS_NULL_AUDIO -I/usr/include -I/home/zouqing/osource/network/src/pjproject-2.7.2/final_x86/include -DPJ_IS_BIG_ENDIAN=0 -DPJ_IS_LITTLE_ENDIAN=1 -fPIC

export OS_CXXFLAGS := $(CC_DEF)PJ_AUTOCONF=1 -g -O2

export OS_LDFLAGS  :=  -lssl -lcrypto -lgcc_s -lc -luuid -lm -lrt -lpthread  -L/usr/local/lib -Wl,-rpath,/usr/local/lib -Wl,--enable-new-dtags -lSDL2  -lavdevice -lavformat -lavcodec -lavutil   -lv4l2

export OS_SOURCES  := 


