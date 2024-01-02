
/* Standard C library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "openssl/rand.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

#include "alg_comm.h"
#include "debug.h"
#define SHA256_DIGEST_SIZE 32
#define SHA256_DATA_SIZE 64
#define _SHA256_DIGEST_LENGTH 8

void smash_random(
    unsigned char *buffer,
    int len)
{
    unsigned char smash_key[32] = {  0x09, 0x1A, 0x09, 0x1A, 0xFF, 0x90, 0x67, 0x90,
                                     0x7F, 0x48, 0x1B, 0xAF, 0x89, 0x72, 0x52, 0x8B,
                                     0x35, 0x43, 0x10, 0x13, 0x75, 0x67, 0x95, 0x4E,
                                     0x77, 0x40, 0xC5, 0x28, 0x63, 0x62, 0x8F, 0x75
                                  };
    KD_ecdsa_hmac_sha256(buffer, len, smash_key, 32, buffer, len);
}

void get_random(
    unsigned char *buffer,
    int len)
{
    RAND_bytes(buffer, len);
    smash_random(buffer, len);
}

int mhash_sha256(
    unsigned char *data,
    unsigned length,
    unsigned char *digest)
{

    SHA256((const unsigned char *)data, length, digest);
    return 0;
}

int ecdsa_hmac_sha256(
    unsigned char *text,
    int text_len,
    unsigned char *key,
    unsigned key_len,
    unsigned char *digest,
    unsigned digest_length)
{
    unsigned char out[SHA256_DIGEST_SIZE] = {0,};
    HMAC(EVP_sha256(),
         key,
         key_len,
         text,
         text_len,
         out,
         NULL);
    memcpy(digest, out, digest_length);
    return 0;
}

void KD_ecdsa_hmac_sha256(
    unsigned char *text,
    unsigned text_len,
    unsigned char *key,
    unsigned key_len,
    unsigned char  *output,
    unsigned length)
{
    unsigned i;

    for(i=0; length/SHA256_DIGEST_SIZE; i++,length-=SHA256_DIGEST_SIZE)
    {
        ecdsa_hmac_sha256(
            text,
            text_len,
            key,
            key_len,
            &output[i*SHA256_DIGEST_SIZE],
            SHA256_DIGEST_SIZE);
        text=&output[i*SHA256_DIGEST_SIZE];
        text_len=SHA256_DIGEST_SIZE;
    }

    if(length>0)
        ecdsa_hmac_sha256(
            text,
            text_len,
            key,
            key_len,
            &output[i*SHA256_DIGEST_SIZE],
            length);

}

