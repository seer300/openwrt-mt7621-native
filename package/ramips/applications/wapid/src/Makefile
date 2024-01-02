include $(TOPDIR)/rules.mk

EXEC = wapid
#LIB_OPENSSL_SRC_PATH = $(ROOTDIR)/user/openssl-0.9.8e
#LIB_OPENSSL_SRC_PATH = $(BUILD_DIR)/openssl-1.0.1e
#LIB_OPENSSL_H_INCLUDE_PATH = $(LIB_OPENSSL_SRC_PATH)/include
#LIB_OPENSSL_LIB_PATH = $(LIB_OPENSSL_SRC_PATH)
#LDFLAGS += -L$(LIB_OPENSSL_LIB_PATH)
CFLAGS  += -DOPENSSL_INC -I$(LIB_OPENSSL_H_INCLUDE_PATH) -DDBG -static

WAPI_OBJS =main.o eloop.o common.o \
	   mlme.o wapi.o sta_info.o \
	   config.o sha256.o sms4.o \
	   wpi_pcrypt.o 

SSL_OBJS +=proc.o cert_info.o x509_cert.o \
	   ecc_crypt.o alg_comm.o debug.o \
	   pack.o cert_auth.o

all: $(EXEC) 

wapid: $(WAPI_OBJS) $(SSL_OBJS)
	#$(MAKE) -C $(LIB_OPENSSL_SRC_PATH) Makefile build_all libcrypto.pc
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(WAPI_OBJS) $(SSL_OBJS) -lcrypto

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o


