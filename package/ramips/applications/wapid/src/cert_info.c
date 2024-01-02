
#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include "structure.h"
#include "common.h"
//#include "config.h"
#include "proc.h"
#include "cert_info.h"
#include "x509_cert.h"
#include "type_def.h"
#include "debug.h"

const struct cert_obj_st_t  *cert_objs[3];

void cert_obj_register( struct cert_obj_st_t *cert_obj)
{
    if(cert_obj->cert_type > 2)
    {
        DBGPRINT(RT_DEBUG_ERROR, "%s: certificate %s has an invalid cert_index %u\n", __func__, cert_obj->cert_name,  cert_obj->cert_type);
        return;
    }

    if (((cert_objs[cert_obj->cert_type]) )!= NULL && ((cert_objs[cert_obj->cert_type]) != cert_obj))
    {
        DBGPRINT(RT_DEBUG_ERROR, "%s: certificate object %s registered with a different template\n", __func__, cert_obj->cert_name);
        return;
    }

    //DBGPRINT(RT_DEBUG_TRACE, "cert_obj_register:cert_obj->cert_type=%d,cert_obj->cert_name:%s\n",cert_obj->cert_type,cert_obj->cert_name);

    cert_obj->cert_bin= (struct cert_bin_t  *)get_buffer(sizeof(struct cert_bin_t));

    if(cert_obj->cert_bin == NULL)
    {
        return ;
    }

    cert_objs[cert_obj->cert_type] = cert_obj;

    DBGPRINT(RT_DEBUG_TRACE, "cert_obj address 	%p\n", cert_obj);
    DBGPRINT(RT_DEBUG_TRACE, "obj[%d] address 		%p\n", cert_obj->cert_type,  cert_objs[cert_obj->cert_type]);
    DBGPRINT(RT_DEBUG_TRACE, "cert_obj_register\n");
    return;

}

void cert_obj_unregister(const struct cert_obj_st_t *cert_obj)
{
    int index = cert_obj->cert_type;

    if(cert_obj->cert_type > 3)
    {
        DBGPRINT(RT_DEBUG_ERROR, "%s: certificate %s has an invalid cert_index %u\n", __func__, cert_obj->cert_name,  cert_obj->cert_type);
        return;
    }

    if ((cert_objs[cert_obj->cert_type] != NULL) && (cert_objs[cert_obj->cert_type] != cert_obj))
    {
        DBGPRINT(RT_DEBUG_TRACE, "cert_obj address 	%p\n", cert_obj);
        DBGPRINT(RT_DEBUG_TRACE, "obj address 		%p\n", cert_objs[cert_obj->cert_type]);
        DBGPRINT(RT_DEBUG_TRACE, "%s: certificate object %s registered with a different template\n", __func__, cert_obj->cert_name);
        return;
    }
    free_buffer((cert_objs[cert_obj->cert_type]->cert_bin), sizeof(struct cert_bin_t));
    cert_objs[index] = NULL;
}

const struct cert_obj_st_t *get_cert_obj(unsigned short index)
{
    if(index == 1)
    {
        return cert_objs[index];
    }
    else
        return NULL;
}

int x509_get_privkey(EC_KEY *tmp_eckey, tkey **ppkey)
{
    tkey *pkey = *ppkey;
    const BIGNUM *priv_key;
    int tkey_len = sizeof(tkey);

    if((ppkey!=NULL) && (pkey  == NULL))
    {
        pkey = (tkey *)get_buffer(tkey_len);
        if(pkey == NULL)
            return -2;

        memset(pkey, 0, tkey_len);
        *ppkey = pkey;
    }

    priv_key = EC_KEY_get0_private_key(tmp_eckey);
    if(priv_key != NULL)
    {
        pkey->length = BN_bn2bin(priv_key, pkey->data);
    }
    else
    {
        free_buffer(pkey, tkey_len);
        return -3;
    }
    return 0;
}

int x509_verify_cert(struct cert_obj_st_t *cert_obj)
{

    EVP_PKEY *asu_pkey=NULL;
    int ret= -1;


    X509 *asu_cert = (X509 *)(cert_obj->asu_cert_st[0]);
    X509 *user_cert = (X509 *)(cert_obj->user_cert_st);

    //X509_print_fp(stdout, asu_cert);
    //X509_print_fp(stdout, user_cert);

    if ((asu_pkey=X509_get_pubkey(asu_cert)) == NULL)
    {
        printf("in %s X509_get_pubkey failure\n", __func__);
        goto err;
    }

    if (X509_verify(asu_cert, asu_pkey) <= 0)
        /* XXX  For the final trusted self-signed cert,
         * this is a waste of time.  That check should
         * optional so that e.g. 'openssl x509' can be
         * used to detect invalid self-signatures, but
         * we don't verify again and again in SSL
         * handshakes and the like once the cert has
         * been declared trusted. */
    {
        printf("in %s X509_verify(asu_cert) failure\n", __func__);
        goto err;
    }
    else if (X509_verify(user_cert, asu_pkey) <= 0)
        /* XXX  For the final trusted self-signed cert,
         * this is a waste of time.  That check should
         * optional so that e.g. 'openssl x509' can be
         * used to detect invalid self-signatures, but
         * we don't verify again and again in SSL
         * handshakes and the like once the cert has
         * been declared trusted. */
    {
        printf("in %s X509_verify(user_cert) failure\n", __func__);
        goto err;
    }
    ret = 0;
err:
    if(asu_pkey)
    {
        DPrintf("in %s:%d free pkey\n", __func__, __LINE__);
        EVP_PKEY_free(asu_pkey);
        asu_pkey=NULL;
    }
    return ret;

}

int x509_verify_3cert(struct cert_obj_st_t *cert_obj)
{

    EVP_PKEY *ca_pkey=NULL;
    int ret= -1;


    X509 *ca_cert = (X509 *)(cert_obj->ca_cert_st);
    X509 *user_cert = (X509 *)(cert_obj->user_cert_st);

    if ((ca_pkey=X509_get_pubkey(ca_cert)) == NULL)
    {
        printf("in %s X509_get_pubkey failure\n", __func__);
        goto err;
    }

    if (X509_verify(user_cert, ca_pkey) <= 0)
        /* XXX  For the final trusted self-signed cert,
         * this is a waste of time.  That check should
         * optional so that e.g. 'openssl x509' can be
         * used to detect invalid self-signatures, but
         * we don't verify again and again in SSL
         * handshakes and the like once the cert has
         * been declared trusted. */
    {
        printf("in %s X509_verify(user_cert) failure\n", __func__);
        goto err;
    }
    ret = 0;
err:
    if(ca_pkey)
    {
        DPrintf("in %s:%d free pkey\n", __func__, __LINE__);
        EVP_PKEY_free(ca_pkey);
        ca_pkey=NULL;
    }
    return ret;

}

INT x509_get_publickey(struct cert_obj_st_t *cert_obj)
{
    int ret= -1;

    cert_obj->asu_pubkey = x509_get_pubkey((X509 *)cert_obj->asu_cert_st[0]);

    if(cert_obj->asu_pubkey == NULL)
    {
        printf("in %s:%d x509_get_pubkey failure \n", __func__,__LINE__);
        goto exit;
    }

    ret = 0;

exit:

    return ret;
}

void print_err()
{
    const char *file_name = "";
    int line = 0;

    ERR_get_error_line(&file_name, &line);
    printf("err at %s:%d\n", file_name, line);
}
void x509_free_obj_data(struct cert_obj_st_t *cert_obj)
{
    int idx;

#if 0
    if(cert_obj->asu_cert_st != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free asu_cert_st\n", __func__, __LINE__);
        X509_free(cert_obj->asu_cert_st);
        cert_obj->asu_cert_st = NULL;
    }
#endif
    for(idx=0; idx<MAX_ID_NO; idx++)
    {
        if (cert_obj->asu_cert_st[idx] != NULL)
        {
            DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free asu_cert_st\n", __func__, __LINE__);
            X509_free(cert_obj->asu_cert_st[idx]);
            cert_obj->asu_cert_st[idx] = NULL;
        }
    }

    if(cert_obj->ca_cert_st != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free ca_cert_st\n", __func__, __LINE__);
        X509_free(cert_obj->ca_cert_st );
        cert_obj->ca_cert_st  = NULL;
    }

    if(cert_obj->user_cert_st != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free user_cert_st\n", __func__, __LINE__);
        X509_free(cert_obj->user_cert_st);
        cert_obj->user_cert_st = NULL;
    }

    if(cert_obj->asu_pubkey != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free asu_pubkey\n", __func__, __LINE__);
        cert_obj->asu_pubkey = free_buffer(cert_obj->asu_pubkey, sizeof(tkey));
    }

    if(cert_obj->ca_pubkey != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free ca_pubkey\n", __func__, __LINE__);
        cert_obj->ca_pubkey = free_buffer(cert_obj->ca_pubkey, sizeof(tkey));
    }

    if(cert_obj->private_key != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free private_key\n", __func__, __LINE__);
        DBGPRINT(RT_DEBUG_TRACE, "cert_obj->private_key address = %p\n",cert_obj->private_key);
        cert_obj->private_key = free_buffer((void *)(cert_obj->private_key), sizeof(tkey));
    }

    if(cert_obj->cert_bin->data != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free cert_bin->data\n", __func__, __LINE__);
        memset(cert_obj->cert_bin->data, 0,  cert_obj->cert_bin->length);
        OPENSSL_free(cert_obj->cert_bin->data);
        cert_obj->cert_bin->data = NULL;
    }
}

#if 0
int get_x509_cert(BIO *bp, struct cert_obj_st_t *cert_obj)
{
    EC_KEY *tmp_pkey=NULL;
    int ret =  EXIT_SUCCESS;
    int len = 0;

    tmp_pkey = PEM_ASN1_read_bio((d2i_of_void *)d2i_ECPrivateKey,
                                 PEM_STRING_ECA,
                                 bp, NULL, NULL,  NULL);
    if(tmp_pkey == NULL)
    {
        const char *file_name = "";
        int line = 0;

        ERR_get_error_line(&file_name, &line);
        printf("err at %s:%d\n", file_name, line);
        printf("unable to read USER's privateKey\n");
        ret = EXIT_FAILURE;
        goto error;
    }

    len = BIO_reset(bp);

    cert_obj->asu_cert_st = PEM_ASN1_read_bio((d2i_of_void *)d2i_X509,
                            PEM_STRING_X509_ASU,
                            bp, NULL, NULL, NULL);

    if(cert_obj->asu_cert_st == NULL)
    {
        printf("unable to read CA's certificate\n");
        ret = EXIT_FAILURE;
        goto error;
    }

    len = BIO_reset(bp);

    cert_obj->user_cert_st = PEM_ASN1_read_bio((d2i_of_void *)d2i_X509,
                             PEM_STRING_X509_USER,
                             bp, NULL,   NULL, NULL);
    if(cert_obj->user_cert_st == NULL)
    {
        printf("unable to read USER's certificate\n");
        ret = EXIT_FAILURE;
        goto error;
    }

    if (!EC_KEY_check_key(tmp_pkey))
    {
        printf("in %s EC_KEY_check_key  failed\n", __func__);
        ret = EXIT_FAILURE;
        goto error;
    }

    ret = x509_verify_cert(cert_obj);
    if(ret != 0)
    {
        printf("in %s :%d call x509_verify_cert  return %d (failure) \n", __func__, __LINE__,ret);
        print_err();
        ret = EXIT_FAILURE;
        goto error;
    }

    len = (*cert_obj->encode)(cert_obj->user_cert_st,
                              &(cert_obj->cert_bin->data),
                              cert_obj->cert_bin->length);
    if(len<0)
    {
        printf("unable to encode usercert\n");
        ret = EXIT_FAILURE;
        goto error;
    }
    cert_obj->cert_bin->length = len;

    ret = x509_get_privkey(tmp_pkey, &(cert_obj->private_key));
    printf("x509_get_privkey cert_obj->private_key=%p\n",cert_obj->private_key);
    if(ret!= 0)
    {
        printf("in %s x509_get_privkey failure ,returns %d\n", __func__,ret);
        ret = EXIT_FAILURE;
        goto error;
    }

    cert_obj->asu_pubkey = x509_get_pubkey((X509 *)cert_obj->asu_cert_st);//) == NULL)

    if(cert_obj->asu_pubkey == NULL)
    {
        printf("in %s:%d x509_get_pubkey failure \n", __func__,__LINE__);
        ret = EXIT_FAILURE;
        goto error;
    }

error:
    if(tmp_pkey != NULL)
    {
        printf("in %s:%d free tmp_pkey\n", __func__, __LINE__);
        EC_KEY_free(tmp_pkey);
    }
    return ret;
}

/*load X509 Certificate */
static int load_x509(char *cert_file, const struct cert_obj_st_t *cert_obj)
{
    BIO *bp_s = NULL;
    BIO *bp_m = NULL;
    unsigned char tmpbuf[256] = {0,};
    int ret =  EXIT_SUCCESS;
    int len = 0;

    printf("load_x509\n");

    if ((bp_s = BIO_new(BIO_s_file())) == NULL)
    {
        printf("unable to create I/O context");
        ret = EXIT_FAILURE;
        goto exit;
    }

    if(!BIO_read_filename(bp_s, cert_file))
    {
        printf("unable to read cert file %s\n ", cert_file);
        ret = EXIT_FAILURE;
        BIO_free(bp_s);
        return ret;
    }
    if(!(bp_m = BIO_new(BIO_s_mem())))
    {
        ret = EXIT_FAILURE;
        goto exit;
    }

    BIO_write(bp_m, "\n", 1);
    while ((len = BIO_read(bp_s, tmpbuf, sizeof( tmpbuf))))
    {
        if(len < 0)
        {
            printf("BIO READ_ERROR in %s:%d\n", __func__, __LINE__);
            ret = EXIT_FAILURE;
            goto exit;
        }
        BIO_write(bp_m, tmpbuf, len);
    }
    BIO_set_flags(bp_m, BIO_FLAGS_MEM_RDONLY);
    /* Decompose Certificate */
    ret = get_x509_cert(bp_m, (struct cert_obj_st_t *)cert_obj);
    if(ret != 0)
    {
        printf("in %s :%d call get_x509_cert  return %d (failure) \n",
               __func__, __LINE__,ret);
    }
exit:
    len = BIO_reset(bp_m);
    BIO_clear_flags(bp_m, BIO_FLAGS_MEM_RDONLY);
    BIO_free(bp_m);
    BIO_free(bp_s);
    return ret;

}
#endif

INT get_asu_x509_cert(BIO *bp, void **pcert_st)
{
    int ret =  EXIT_SUCCESS;
    int len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> get_asu_x509_cert\n");

    len = BIO_reset(bp);

    *pcert_st = PEM_ASN1_read_bio((d2i_of_void *)d2i_X509,
                                  PEM_STRING_X509,
                                  bp, NULL, NULL, NULL);

    if(*pcert_st == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to read CA's certificate\n");
        ret = EXIT_FAILURE;
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== get_asu_x509_cert\n");

    return ret;
}

int get_ca_x509_cert(BIO *bp, struct cert_obj_st_t *cert_obj)
{
    int ret =  EXIT_SUCCESS;


    cert_obj->ca_cert_st = PEM_ASN1_read_bio((d2i_of_void *)d2i_X509,
                           PEM_STRING_X509,
                           bp, NULL, NULL, NULL);

    if(cert_obj->ca_cert_st == NULL)
    {
        printf("unable to read CA's certificate\n");
        ret = EXIT_FAILURE;

    }

    cert_obj->ca_pubkey = x509_get_pubkey((X509 *)cert_obj->ca_cert_st);

    if(cert_obj->ca_pubkey == NULL)
    {
        printf("in %s:%d x509_get_pubkey failure \n", __func__,__LINE__);
        ret = EXIT_FAILURE;

    }

    return ret;
}


//static INT load_asu_x509(char *asu_cert_file,struct cert_obj_st_t *cert_obj)
static INT load_asu_x509(char *asu_cert_file,void **pcert_st)
{
    BIO *bp_s = NULL;
    BIO *bp_m = NULL;
    unsigned char tmpbuf[256] = {0,};
    int ret =  EXIT_SUCCESS;
    int len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> load_asu_x509\n");

    if ((bp_s = BIO_new(BIO_s_file())) == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to create I/O context");
        ret = EXIT_FAILURE;
        goto exit;
    }

    if(!BIO_read_filename(bp_s, asu_cert_file))
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to read cert file %s\n ", asu_cert_file);
        ret = EXIT_FAILURE;
        BIO_free(bp_s);
        return ret;
    }
    if(!(bp_m = BIO_new(BIO_s_mem())))
    {
        ret = EXIT_FAILURE;
        goto exit;
    }

    BIO_write(bp_m, "\n", 1);
    while ((len = BIO_read(bp_s, tmpbuf, sizeof( tmpbuf))))
    {
        if(len < 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "BIO READ_ERROR in %s:%d\n", __func__, __LINE__);
            ret = EXIT_FAILURE;
            goto exit;
        }

        BIO_write(bp_m, tmpbuf, len);
    }
    BIO_set_flags(bp_m, BIO_FLAGS_MEM_RDONLY);

    /* Decompose Certificate */
    ret = get_asu_x509_cert(bp_m, pcert_st);

    if(ret != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR,"in %s :%d call get_asu_x509_cert  return %d (failure) \n", __func__, __LINE__,ret);
    }

exit:
    len = BIO_reset(bp_m);
    BIO_clear_flags(bp_m, BIO_FLAGS_MEM_RDONLY);
    BIO_free(bp_m);
    BIO_free(bp_s);

    DBGPRINT(RT_DEBUG_TRACE, "<====== load_asu_x509\n");
    return ret;
}

static INT load_ca_x509(char *ca_cert_file,struct cert_obj_st_t *cert_obj)
{
    BIO *bp_s = NULL;
    BIO *bp_m = NULL;
    unsigned char tmpbuf[256] = {0,};
    int ret =  EXIT_SUCCESS;
    int len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> load_ca_x509\n");

    if ((bp_s = BIO_new(BIO_s_file())) == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to create I/O context");
        ret = EXIT_FAILURE;
        goto exit;
    }

    if(!BIO_read_filename(bp_s, ca_cert_file))
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to read cert file %s\n ", ca_cert_file);
        ret = EXIT_FAILURE;
        BIO_free(bp_s);
        return ret;
    }
    if(!(bp_m = BIO_new(BIO_s_mem())))
    {
        ret = EXIT_FAILURE;
        goto exit;
    }

    BIO_write(bp_m, "\n", 1);
    while ((len = BIO_read(bp_s, tmpbuf, sizeof( tmpbuf))))
    {
        if(len < 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "BIO READ_ERROR in %s:%d\n", __func__, __LINE__);
            ret = EXIT_FAILURE;
            goto exit;
        }

        BIO_write(bp_m, tmpbuf, len);
    }
    BIO_set_flags(bp_m, BIO_FLAGS_MEM_RDONLY);

    /* Decompose Certificate */
    ret = get_ca_x509_cert(bp_m, cert_obj);

    if(ret != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR,"in %s :%d call get_ca_x509_cert  return %d (failure) \n", __func__, __LINE__,ret);
    }

exit:
    len = BIO_reset(bp_m);
    BIO_clear_flags(bp_m, BIO_FLAGS_MEM_RDONLY);
    BIO_free(bp_m);
    BIO_free(bp_s);

    DBGPRINT(RT_DEBUG_TRACE, "<====== load_ca_x509\n");
    return ret;
}

INT get_user_x509_cert(BIO *bp, struct cert_obj_st_t *cert_obj)
{
    EC_KEY *tmp_pkey=NULL;
    int ret =  EXIT_SUCCESS;
    int len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> get_user_x509_cert\n");

    tmp_pkey = PEM_ASN1_read_bio((d2i_of_void *)d2i_ECPrivateKey,
                                 PEM_STRING_ECA,
                                 bp, NULL, NULL,  NULL);
    if(tmp_pkey == NULL)
    {
        const char *file_name = "";
        int line = 0;

        ERR_get_error_line(&file_name, &line);
        DBGPRINT(RT_DEBUG_TRACE, "err at %s:%d\n", file_name, line);
        DBGPRINT(RT_DEBUG_TRACE, "unable to read USER's privateKey\n");
        ret = EXIT_FAILURE;

        goto error;
    }

    len = BIO_reset(bp);

    cert_obj->user_cert_st = PEM_ASN1_read_bio((d2i_of_void *)d2i_X509,
                             PEM_STRING_X509,
                             bp, NULL,   NULL, NULL);
    if(cert_obj->user_cert_st == NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "unable to read USER's certificate\n");
        ret = EXIT_FAILURE;
        goto error;
    }

    if (!EC_KEY_check_key(tmp_pkey))
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s EC_KEY_check_key  failed\n", __func__);
        ret = EXIT_FAILURE;
        goto error;
    }

    ret = x509_get_privkey(tmp_pkey, &(cert_obj->private_key));
    printf("x509_get_privkey cert_obj->private_key=%p\n",cert_obj->private_key);
    if(ret!= 0)
    {
        printf("in %s x509_get_privkey failure ,returns %d\n", __func__,ret);
        ret = EXIT_FAILURE;
        goto error;
    }

error:

    if(tmp_pkey != NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, "in %s:%d free tmp_pkey\n", __func__, __LINE__);
        EC_KEY_free(tmp_pkey);
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== get_user_x509_cert\n");

    return ret;
}

static INT load_user_x509(char *user_cert_file,struct cert_obj_st_t *cert_obj)
{
    BIO *bp_s = NULL;
    BIO *bp_m = NULL;
    unsigned char tmpbuf[256] = {0,};
    int ret =  EXIT_SUCCESS;
    int len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> load_user_x509\n");

    if ((bp_s = BIO_new(BIO_s_file())) == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to create I/O context");
        ret = EXIT_FAILURE;
        goto exit;
    }

    if(!BIO_read_filename(bp_s, user_cert_file))
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to read cert file %s\n ", user_cert_file);
        ret = EXIT_FAILURE;
        BIO_free(bp_s);
        return ret;
    }
    if(!(bp_m = BIO_new(BIO_s_mem())))
    {
        ret = EXIT_FAILURE;
        goto exit;
    }

    BIO_write(bp_m, "\n", 1);
    while ((len = BIO_read(bp_s, tmpbuf, sizeof( tmpbuf))))
    {
        if(len < 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "BIO READ_ERROR in %s:%d\n", __func__, __LINE__);
            ret = EXIT_FAILURE;
            goto exit;
        }

        BIO_write(bp_m, tmpbuf, len);
    }
    BIO_set_flags(bp_m, BIO_FLAGS_MEM_RDONLY);

    len = BIO_reset(bp_m);

    /* Decompose Certificate */
    ret = get_user_x509_cert(bp_m, cert_obj);

    if(ret != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR,"in %s :%d call get_user_x509_cert  return %d (failure) \n", __func__, __LINE__,ret);
    }

exit:
    len = BIO_reset(bp_m);
    BIO_clear_flags(bp_m, BIO_FLAGS_MEM_RDONLY);
    BIO_free(bp_m);
    BIO_free(bp_s);

    DBGPRINT(RT_DEBUG_TRACE, "<====== load_user_x509\n");
    return ret;
}

//static INT load_verify_x509(char *asu_cert_file, char *user_cert_file, const struct cert_obj_st_t *cert_obj)
static INT load_verify_x509(struct wapi_device_config *wapi_conf, const struct cert_obj_st_t *cert_obj)
{
    int len = 0;
    int ret =  EXIT_SUCCESS;
    int idx;

    DBGPRINT(RT_DEBUG_TRACE, "======> load_verify_x509\n");

    //ret = load_user_x509(user_cert_file, (struct cert_obj_st_t *)cert_obj);
    ret = load_user_x509(wapi_conf->ae_name, (struct cert_obj_st_t *)cert_obj);

    if(ret != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call load_user_x509  return %d (failure) \n", __func__, __LINE__,ret);
        print_err();
        ret = EXIT_FAILURE;
        goto exit;
    }

#if 0
    //ret = load_asu_x509(asu_cert_file, (struct cert_obj_st_t *)cert_obj);
    ret = load_asu_x509(wapi_conf->as_name, (void **)&cert_obj->asu_cert_st);

    if(ret != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call load_asu_x509  return %d (failure) \n", __func__, __LINE__,ret);
        print_err();
        ret = EXIT_FAILURE;
        goto exit;
    }
#endif
    for(idx=0; idx<wapi_conf->as_no; idx++)
    {
        ret = load_asu_x509(wapi_conf->as_name[idx], (void **)&cert_obj->asu_cert_st[idx]);

        if(ret != 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call load_asu_x509  return %d (failure), idx: %d \n", __func__, __LINE__,ret, idx);
            print_err();
            ret = EXIT_FAILURE;
            goto exit;
        }
    }

    if (wapi_conf->cert_mode == THREE_CERTIFICATE_MODE)
    {
        ret = load_ca_x509(wapi_conf->ca_name, (struct cert_obj_st_t *)cert_obj);

        if(ret != 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call load_ca_x509	return %d (failure) \n", __func__, __LINE__,ret);
            print_err();
            ret = EXIT_FAILURE;
            goto exit;
        }

        ret = x509_verify_3cert((struct cert_obj_st_t *)cert_obj);
        if(ret != 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call x509_verify_3cert  return %d (failure) \n", __func__, __LINE__,ret);
            print_err();
            ret = EXIT_FAILURE;
            goto exit;
        }
    }
    else /* 2 certificates: user, asu */
    {
        ret = x509_verify_cert((struct cert_obj_st_t *)cert_obj);
        if(ret != 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call x509_verify_cert  return %d (failure) \n", __func__, __LINE__,ret);
            print_err();
            ret = EXIT_FAILURE;
            goto exit;
        }
    }
    len = (*cert_obj->encode)(cert_obj->user_cert_st,
                              &(cert_obj->cert_bin->data),
                              cert_obj->cert_bin->length);
    if(len<0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "unable to encode usercert\n");
        print_err();
        ret = EXIT_FAILURE;
        goto exit;
    }

    cert_obj->cert_bin->length = len;
    DBGPRINT(RT_DEBUG_TRACE, "cert_obj->cert_bin->length = %d\n", cert_obj->cert_bin->length);

    ret = x509_get_publickey((struct cert_obj_st_t *)cert_obj);

    if(ret != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "in %s :%d call x509_get_publickey  return %d (failure) \n", __func__, __LINE__,ret);
        print_err();
        ret = EXIT_FAILURE;
        goto exit;
    }

exit:

    if (ret != EXIT_SUCCESS)
        wapi_unregister_certificate();

    DBGPRINT(RT_DEBUG_TRACE, "<====== load_verify_x509\n");
    return ret;
}

INT32 wapi_register_certificate(PRTMP_ADAPTER pAd)
{
    int res =  -1;
    unsigned short  index = pAd->cert_info.config.used_cert;

    //DBGPRINT(RT_DEBUG_TRACE, "User Certificate = %d\n",pAd->cert_info.config.used_cert);
    DBGPRINT(RT_DEBUG_TRACE, "User Certificate are %s\n",(pAd->cert_info.config.used_cert == 1) ? "X.509 v3" : "not support certificate");

    switch(index)
    {
        case 0:
            //res = load_none(eloop.cert_info.config.cert_name, cert_objs[index]);
            break;
        case 1:
            x509_free_obj_data((struct cert_obj_st_t *)cert_objs[index]);

            //res = load_x509(pAd->cert_info.config.cert_name, cert_objs[index]);
            //res = load_verify_x509(pAd->cert_info.config.as_name, pAd->cert_info.config.ae_name, cert_objs[index]);
            res = load_verify_x509(&pAd->cert_info.config, cert_objs[index]);
            break;
        case 2:
            //gbw_free_obj_data((struct cert_obj_st_t *)cert_objs[index]);
            //res = load_gbw(apcert_info->config.cert_name, cert_objs[index]);
            break;
        default:
            break;
    }

    if(res == 0)
    {
        pAd->cert_info.local_cert_obj = (struct cert_obj_st_t *)cert_objs[index];
    }
    return res;
}

void wapi_unregister_certificate(void)
{
    x509_free_obj_data((struct cert_obj_st_t *)cert_objs[1]);
}

INT cmp_oid(unsigned char *in , unsigned short len)
{
    char pubkey_alg_para_oid_der[16] = {0x06, 0x09,0x2a,0x81,0x1c, 0xd7,0x63,0x01,0x01,0x02,0x01};

    if(len != 11)
    {
        return -1;
    }
    if(memcmp(pubkey_alg_para_oid_der, in, 11)!=0)
    {
        return -2;
    }
    return 0;
}

