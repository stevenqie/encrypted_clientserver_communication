# Hints

## Compile OpenSSL

1. Download openssl library

```
git clone https://github.com/openssl/openssl.git
```

2. compile openssl

```
cd openssl
./config
make
```

3. Modify Makefile: change OPENSSL to your openssl dir, add entries for your other files (e.g., client.c)

4. Compile the server and client binary

```
make
```

By default, the server is listening to port 12000

## Server

A working Makefile and a copy of server in Module 3 is provided. Please understand every function in server. You can use them for previous Modules. You can also run the server on your local machine to debug your client in Module 3.

## Generate keys
1. Generate OpenSSL Private Key

```
openssl genrsa -out private.pem 2048
```

2. Derive Public key
```
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```