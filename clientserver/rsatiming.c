#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "timer.c"

int main() {
    int padding = RSA_PKCS1_PADDING;
    RSA* key = NULL;

    FILE* public_key_file = fopen("../publickey.pem", "rb");
    if (!public_key_file) {
        printf("Cant open file");
        return 1;
    }
    key = PEM_read_RSA_PUBKEY(public_key_file, key, NULL, NULL);
    fclose(public_key_file);
    if (!key) {
        printf("Failed to read the RSA public key.\n");
        return 1;
    }
    for (int i = 0; i < 1000000; i++) {
        unsigned char plaintext[16];
        unsigned char ciphertext[256];
        RAND_bytes(&plaintext, 16);
        u_int64_t t1 = timer_start();
        int result = RSA_public_encrypt(16, plaintext, ciphertext, key, padding);
        u_int64_t t2 = timer_stop();
        printf("%d, ", (t2-t1));
    }
    return 0;
}

