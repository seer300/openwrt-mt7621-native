
#ifndef _ECC_CCRYPT_H
#define _ECC_CCRYPT_H

#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/ecdh.h"
#include "openssl/evp.h"
#include "openssl/err.h"

#define EC962_PRIVKEY_LEN	24
#define EC962_SIGN_LEN		48


int point2bin(EC_KEY *eckey, unsigned char *pub_s , int pub_sl);
EC_KEY *geteckey_by_curve(int nid );
EC_KEY * octkey2eckey(const unsigned char *pub_s, int pub_sl, const unsigned char *priv_s, int priv_sl,	int nid);

int sign2bin(EC_KEY  *eckey, ECDSA_SIG *s, unsigned char *signature,  int *siglen);
int   ecc192_verify(const unsigned char *pub_s, int pub_sl, unsigned char *in ,  int in_len, unsigned char *sig,int sign_len);
int ecc192_sign(const unsigned char *priv_s, int priv_sl,	const unsigned char * in, int in_len, unsigned char *out);

int ecc192_ecdh(const unsigned char *apub_s, int apub_sl,
				const unsigned char *bpriv_s, int bpriv_sl,
				const unsigned char *bpub_s, int bpub_sl,
				unsigned char *key, int keyl);
int ecc192_verify_key(const unsigned char *pub_s, int pub_sl, const unsigned char *priv_s, int priv_sl);
#endif
