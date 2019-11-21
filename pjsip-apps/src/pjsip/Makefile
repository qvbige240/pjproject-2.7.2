.SUFFIXES : .x .o .c .s

#ROOT = /usr/local/arm_linux_4.2/
ROOT=$(shell /bin/pwd)
INSTALL=$(ROOT)/../../../final_x86
LIB = $(INSTALL)/lib
LIBSYS = /usr/lib
INC = $(INSTALL)/include
INCSYS = /usr/include

STATIC_LIBS=$(LIB)/libpjsua-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjsip-ua-x86_64-unknown-linux-gnu.a $(LIB)/libpjsip-simple-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjsip-x86_64-unknown-linux-gnu.a $(LIB)/libpjmedia-codec-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjmedia-x86_64-unknown-linux-gnu.a $(LIB)/libpjmedia-videodev-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjmedia-audiodev-x86_64-unknown-linux-gnu.a $(LIB)/libpjmedia-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjnath-x86_64-unknown-linux-gnu.a $(LIB)/libpjlib-util-x86_64-unknown-linux-gnu.a  \
$(LIB)/libsrtp-x86_64-unknown-linux-gnu.a $(LIB)/libresample-x86_64-unknown-linux-gnu.a \
$(LIB)/libgsmcodec-x86_64-unknown-linux-gnu.a $(LIB)/libspeex-x86_64-unknown-linux-gnu.a \
$(LIB)/libilbccodec-x86_64-unknown-linux-gnu.a $(LIB)/libwebrtc-x86_64-unknown-linux-gnu.a \
$(LIB)/libpj-x86_64-unknown-linux-gnu.a

CC=gcc -O2 -I$(INC) -I$(INCSYS)
WEC_LDFLAGS=-L$(LIB) -L$(LIBSYS)
STRIP=strip

TARGET = sample-sip
SRCS := *.c
LIBS= -lssl -lcrypto -luuid -lm -lrt -lpthread

all: 
	$(CC) $(WEC_LDFLAGS) $(SRCS) -o $(TARGET) $(STATIC_LIBS) $(LIBS)
	$(STRIP) $(TARGET) 

clean:
	rm -f *.o 
	rm -f *.x 
	rm -f *.flat
	rm -f *.map
	rm -f temp
	rm -f *.img
	rm -f $(TARGET)	
	rm -f *.gdb
	rm -f *.bak
