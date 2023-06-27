#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include "timer.c"


int main() {
    AES_KEY aesKey;
    unsigned char key[32];
    RAND_bytes(&key, 32);
    for (int i = 0; i < 1000000; i++) {
        AES_KEY aesKey;
        
        //16 byte data that is going to be encrypted and then is just randomized 
        unsigned char plaintext[16];
        RAND_bytes(&plaintext, sizeof plaintext);
        unsigned char ciphertext[16];

        AES_set_encrypt_key(&key, 256, &aesKey);
        uint64_t t1 = timer_start();
        AES_encrypt(plaintext, ciphertext, &aesKey);
        uint64_t t2 = timer_stop();

        printf("%d, ", (t2-t1));

    }
    return 0;

}

