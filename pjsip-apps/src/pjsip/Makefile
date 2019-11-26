.SUFFIXES : .x .o .c .s

#ROOT = /usr/local/arm_linux_4.2/
ROOT=$(shell /bin/pwd)
INSTALL=$(ROOT)/../../../final_x86
LIB = $(INSTALL)/lib
LIBSYS = /usr/lib
INC = $(INSTALL)/include
INCSYS = /usr/include
INC_SIP = $(ROOT)/inc

STATIC_LIBS=$(LIB)/libpjsip-ua-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjsip-simple-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjsdp-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjsip-x86_64-unknown-linux-gnu.a \
$(LIB)/libpjlib-util-x86_64-unknown-linux-gnu.a \
$(LIB)/libpj-x86_64-unknown-linux-gnu.a

CC=gcc -g -O0 -I$(INC) -I$(INC_SIP) -I$(INCSYS)
WEC_LDFLAGS=-L$(LIB) -L$(LIBSYS)
STRIP=strip

TARGET = sample-sip
SRCS := *.c
LIBS= -lssl -lcrypto -luuid -lm -lrt -lpthread

all: 
	$(CC) $(WEC_LDFLAGS) $(SRCS) -o $(TARGET) $(STATIC_LIBS) $(LIBS)
#	$(STRIP) $(TARGET) 

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
