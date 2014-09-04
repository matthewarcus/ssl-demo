# ----------------------------------------------------------------------------
# "DO WHAT THOU WILT license" (Revision 666):
# Copyright Matthew Arcus (c) 2014.
# Please retain this notice.
# You can do whatever you like with this code.
# ----------------------------------------------------------------------------

EXES := ssl_client ssl_server

OPENSSL := openssl/current
#OPENSSL := ../libressl
INC := -I$(OPENSSL)/include
LIB := -L$(OPENSSL) 
#LIB += -Lgperftools-2.1/.libs
#EXTRA += -ltcmalloc
#EXTRA += -lefence

all: $(EXES)

$(EXES): %: %.o
	g++ -Wall -O2 -g $(LIB) -o $@ $^ -lssl -lcrypto -ldl $(EXTRA)


ssl_client ssl_server: ssl_lib.o

ssl_client.o ssl_server.o ssl_lib.o: %.o: %.cpp ssl_lib.h
	g++ -Wall -O2 -g $(INC) $(EXTRA) -c -Wshadow -o $@ $<


clean:
	rm -f $(EXES) *.o

cleanall: clean
	rm -rf clientcerts
	rm -f *.pem */*.pem *.srl
