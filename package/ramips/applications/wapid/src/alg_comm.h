
#ifndef _ALG_COMM_H
#define _ALG_COMM_H

void smash_random(
		unsigned char *buffer,
		int len);
void get_random(
		unsigned char *buffer,
		int len);
int mhash_sha256(
		unsigned char *data,
		unsigned length,
		unsigned char *digest);
void KD_ecdsa_hmac_sha256(
		unsigned char *text,
		unsigned text_len,
		unsigned char *key,
		unsigned key_len,
		unsigned char  *output,
		unsigned length);
int ecdsa_hmac_sha256(
		unsigned char *text,
		int text_len, 
		unsigned char *key,
		unsigned key_len,
		unsigned char *digest,
		unsigned digest_length);
#endif
