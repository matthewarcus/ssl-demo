# ----------------------------------------------------------------------------
# "DO WHAT THOU WILT license" (Revision 666):
# Copyright Matthew Arcus (c) 2014.
# Please retain this notice.
# You can do whatever you like with this code.
# ----------------------------------------------------------------------------

CXX := g++
EXES := ssl_client ssl_server

# Define LIBRESSL to be the root of the desired LibreSSL source tree
# else define OPENSSL to be the root of the desired OpenSSL source tree.
# If neither defined, installed version of OpenSSL will be used.

# eg:
#LIBRESSL := libressl/current
#OPENSSL := openssl/current
#OPENSSL := openssl/devel

# Be careful that you really are getting the right headers & not eg. including
# LibreSSL headers but linking with OpenSSL libraries or vice versa, though
# we now check at runtime for consistency.

ifdef LIBRESSL
INC += -I$(LIBRESSL)/include
EXTRA += -DNO_SRP
OPENSSL_LIBS := $(LIBRESSL)/ssl/.libs/libssl.a $(LIBRESSL)/crypto/.libs/libcrypto.a -lrt
else
ifdef OPENSSL
INC += -I$(OPENSSL)/include
LIB += -L$(OPENSSL)
endif
OPENSSL_LIBS := -lssl -lcrypto -lpthread
endif

# Use our main ca cert to represent all certs made by makecerts
CERTS := ca.pem

all: $(EXES) $(CERTS)

$(EXES): %: %.o
	$(CXX) -Wall -g $(LIB) -o $@ $^ $(OPENSSL_LIBS) -ldl

ssl_client ssl_server: ssl_lib.o

ssl_client.o ssl_server.o ssl_lib.o: %.o: %.cpp ssl_lib.h
	$(CXX) -Wall -g -O2 $(INC) $(EXTRA) -c -Wshadow -o $@ $<

test: test.sh $(EXES) $(CERTS)
	./test.sh

$(CERTS): makecerts
	./makecerts

clean:
	rm -f $(EXES) *.o

cleanall: clean
	rm -rf clientcerts
	rm -f *.pem */*.pem *.srl

.PHONY: clean test all

