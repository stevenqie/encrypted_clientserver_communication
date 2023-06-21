CC=gcc
OPENSSL=../../../openssl
INCLUDE=$(OPENSSL)/include/
CFLAGS=-c -I$(INCLUDE) 

all: server

server: server.c
	$(CC) server.c -I$(INCLUDE) -L$(OPENSSL) -o server $(OPENSSL)/libcrypto.a -ldl -lpthread

clean:
	rm -rf server