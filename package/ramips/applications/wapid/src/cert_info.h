
#ifndef __CERT_INFO__H__
#define __CERT_INFO__H__
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include "structure.h"
#include "main_def.h"

#define CERT_OBJ_NONE 0
#define  CERT_OBJ_X509 1
#define  CERT_OBJ_GBW  2
#define	GETSHORT(frm, v) do { (v) = (((frm[0]) <<8) | (frm[1]))& 0xffff;} while (0)

typedef certificate gwb_cert;

struct cert_obj_st_t{
	int cert_type;
	char *cert_name;
	void *asu_cert_st[MAX_ID_NO];
	tkey *asu_pubkey;
	void *ca_cert_st;
	tkey *ca_pubkey;	
	void *user_cert_st;
	tkey *private_key;
	struct cert_bin_t  *cert_bin;
	struct cert_bin_t  *asu_cert_bin;
	
	/*(void*)  (*obj_new)(void);
	int  (*obj_free)(void **cert_st);*/
	void*  (*obj_new)(void);
	void  (*obj_free)(void **cert_st);
	int  (*decode)(void **cert_st, unsigned char *in, int in_len);
	int (*encode)(void *cert_st, unsigned char **out, int out_len);
	int (*cmp)(void *cert_bin_a, void *cert_bin_b);
	void* (*get_public_key)(void *cert_st);
	void* (*get_subject_name)(void *cert_st);
	void* (*get_issuer_name)(void *cert_st);
	void* (*get_serial_number)(void *cert_st);
	int (*verify_key)(const unsigned char *pub_s, int pub_sl, const unsigned char *priv_s, int priv_sl);
	int (*sign)(const unsigned char *priv_s, int priv_sl,
			//const unsigned char *pub_s, int pub_sl,
			const unsigned char * in, int in_len, 
			unsigned char *out);
	int (*verify)(const unsigned char *pub_s, int pub_sl, unsigned char *in ,  int in_len, unsigned char *sig,int sign_len);
};

void cert_obj_register(struct cert_obj_st_t *cert_obj);
void cert_obj_unregister(const struct cert_obj_st_t *cert_obj);
INT cmp_oid(unsigned char *in , unsigned short len);

INT x509_get_publickey(struct cert_obj_st_t *cert_obj);
int get_x509_cert(BIO *bp, struct cert_obj_st_t *cert_obj);
INT get_asu_x509_cert(BIO *bp, void **pcert_st);
INT get_user_x509_cert(BIO *bp, struct cert_obj_st_t *cert_obj);
void x509_free_obj_data(struct cert_obj_st_t *cert_obj);
const struct cert_obj_st_t *get_cert_obj(unsigned short index);
int register_certificate(void);

INT32 wapi_register_certificate(PRTMP_ADAPTER pAd);
void wapi_unregister_certificate(void);

#endif
