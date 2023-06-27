CC=gcc
OPENSSL=/Users/stevenqie/Documents/GitHub/socket-programming/openssl
INCLUDE=$(OPENSSL)/include/
CFLAGS=-c -I$(INCLUDE) 

all: server.o client.o

p1: aes.o rsa.o
	./aes.o > aes.txt
	./rsa.o > rsa.txt 

rsa.o: rsatiming.c timer.c
	$(CC) rsatiming.c timer.c -w -I $(INCLUDE) -L$(OPENSSL) -o rsa.o $(OPENSSL)/libcrypto.a -ldl

aes.o: aestiming.c timer.c
	$(CC) aestiming.c timer.c -w -I $(INCLUDE) -L$(OPENSSL) -o aes.o $(OPENSSL)/libcrypto.a -ldl

server.o: server.c
	$(CC) server.c -I$(INCLUDE) -L$(OPENSSL) -o server.o $(OPENSSL)/libcrypto.a -ldl -lpthread

client.o: client.c
	$(CC) client.c -I$(INCLUDE) -L$(OPENSSL) -o client.o $(OPENSSL)/libcrypto.a -ldl -lpthread

clean:
	rm *.o