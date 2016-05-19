#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define SERVER 1
#define CLIENT 0

#define PAGE_SIZE 4096

typedef struct {
	struct sockaddr_in dest;
	struct sockaddr_in src;
	int len;
	char *key;
	int sd;
} nw_param;

struct ctr_state 
{ 
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num; 
    unsigned char ecount[AES_BLOCK_SIZE]; 
};

struct ctr_state state;
unsigned char iv[AES_BLOCK_SIZE];
AES_KEY aes_key;
