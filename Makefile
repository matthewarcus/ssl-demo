EXES := ssl_client ssl_server

OPENSSL := openssl/current
INC := -I$(OPENSSL)/include
LIB := -L$(OPENSSL) 

all: $(EXES)

$(EXES): %: %.o ssl_lib.o
	g++ -Wall -O3 -g $(LIB) -o $@ $^ -lssl -lcrypto -ldl

%.o: %.cpp ssl_lib.h
	g++ -Wall -O3 -g $(INC) -c -Wshadow -o $@ $<


clean:
	rm -f $(EXES) *.o

cleanall: clean
	rm -rf clientcerts
	rm -f *.pem */*.pem *.srl

