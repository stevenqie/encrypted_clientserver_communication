#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

int padding = RSA_PKCS1_PADDING;
AES_KEY *expanded;

/**
 * Configuration.
 */
struct Config
{
  char ip[15];
  uint16_t port_;
};

RSA *createRSA(unsigned char *key, int public)
{
  RSA *rsa = NULL;
  BIO *keybio;
  keybio = BIO_new_mem_buf(key, -1);
  if (keybio == NULL)
  {
    printf("Failed to create key BIO");
    return 0;
  }
  if (public)
  {
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  }
  else
  {
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  }
  if (rsa == NULL)
  {
    printf("Failed to create RSA");
  }

  return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key,
                   unsigned char *encrypted)
{
  RSA *rsa = createRSA(key, 1);
  int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
                    unsigned char *decrypted)
{
  RSA *rsa = createRSA(key, 0);
  int result =
      RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
  return result;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *key,
                    unsigned char *encrypted)
{
  RSA *rsa = createRSA(key, 0);
  int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
  return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key,
                   unsigned char *decrypted)
{
  RSA *rsa = createRSA(key, 1);
  int result =
      RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
  return result;
}

void printHelp(char *argv[])
{
  fprintf(
      stderr,
      "Usage: %s [-p port number] "
      "\n",
      argv[0]);
  exit(EXIT_FAILURE);
}


void parseOpt(int argc, char *argv[], struct Config *config)
{
  int opt;
  while ((opt = getopt(argc, argv, "p:")) != -1)
  {
    switch (opt)
    {
    case 'p':
      config->port_ = atoi(optarg);
      break;
    default:
      printHelp(argv);
    }
  }
}

/**
 * Set a read timeout.
 *
 * @param sk Socket.
 * @return True if successful.
 */
static bool SetReadTimeout(const int sk)
{
  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
  {
    printf("unable to set read timeout\n");
    return false;
  }

  return true;
}

/**
 * Read n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to read.
 * @return True if successful.
 */
static bool ReadBytes(const int sk, char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    if (!SetReadTimeout(sk))
    {
      return false;
    }

    int ret = recv(sk, ptr, ptr - buf + n, 0);
    if (ret <= 0)
    {
      //LOG(ERROR) << "unable to receive on socket";
      return false;
    }

    ptr += ret;
  }

  return true;
}

/**
 * Write n bytes.
 *
 * @param sk Socket.
 * @param buf Buffer.
 * @param n Number of bytes to write.
 * @return True if successful.
 */
static bool WriteBytes(const int sk, const char *buf, const size_t n)
{
  char *ptr = buf;
  while (ptr < buf + n)
  {
    int ret = send(sk, ptr, n - (ptr - buf), 0);
    if (ret <= 0)
    {
      printf("unable to send on socket\n");
      return false;
    }

    ptr += ret;
  }

  return true;
}

static void RunClient(struct Config *conf)
{
  int client_fd, messageSize, i;
  struct sockaddr_in serv_addr;
  unsigned char aes_key[16];
  char buffer[8192]={0};
  char enc_key[8192]={0};
  char plain[16];
  memset(&serv_addr, 0, sizeof(serv_addr));

  // Setup the socket connection
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
  {
    printf("unable to create client socket\n");
    return;
  }

  printf("connecting to port: %i\n", conf->port_);

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(conf->port_);

  if (inet_pton(AF_INET, conf->ip, &serv_addr.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return;
  }
 
  if ((client_fd = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
    printf("\nConnection Failed \n");
    return;
  }
  

  //Get public key from server
  if (!ReadBytes(sock, &messageSize, sizeof(messageSize)))
  {
    printf("unable to read server's public key size\n");
    return;
  }
   printf("server's key size: %i\n", messageSize);
 
  if (!ReadBytes(sock, buffer, messageSize))
  {
    printf("unable to read server's public key\n");
    return;
  }
  
  messageSize = public_encrypt(aes_key, 16, buffer, enc_key);
  WriteBytes(sock, &messageSize, sizeof(messageSize));
  WriteBytes(sock, enc_key, sizeof(enc_key));

  if (!ReadBytes(sock, buffer, 16))
  {
    printf("can't read server secret\n");
    return;
  }

  expanded = (AES_KEY *)malloc(sizeof(AES_KEY));
  AES_set_decrypt_key(aes_key, 128, expanded);
  AES_decrypt(buffer, plain, expanded);
  plain[16] = '\0';
  printf("Server's secret:\n");
  for(i = 0; i <= 16; i++){
    printf("%c", plain[i]);
  }
  printf("\n");

  close(client_fd);
}

int main(int argc, char **argv)
{
  struct Config conf;
  conf.port_ = 12000;
  strcpy(conf.ip, "127.0.0.1");
  parseOpt(argc, argv, &conf);
  RunClient(&conf);
  return 0;
}
