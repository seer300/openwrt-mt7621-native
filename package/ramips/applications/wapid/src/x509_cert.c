
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "structure.h"
#include "cert_info.h"
#include "ecc_crypt.h"
#include "proc.h"
#include "debug.h"

static void * X509_wapi_new(void)
{
    return NULL;
}
static void X509_obj_free(void **cert_st)
{
    X509 *a = (X509 *)(*cert_st);
    X509_free(a);
    *cert_st = NULL;
    return ;
}

static  int X509_decode(void **cert_st, unsigned char *in, int in_len)
{
    const unsigned char  *p = NULL;

    DBGPRINT(RT_DEBUG_TRACE, "X509_decode \n");

    X509 **x = (X509 **)cert_st;
    /* Something to setup buf and len */
    p = in;
    if(!d2i_X509(x, &p, in_len))
    {
        DBGPRINT(RT_DEBUG_ERROR, "X509_decode fail \n");
        return -1;
        /* Some error */
    }

    DBGPRINT(RT_DEBUG_TRACE, "X509_decode success \n");
    return 0;
}

static int X509_encode(void *cert_st, unsigned char **out, int outlen)
{
    int len = 0;

    if((out != NULL) && (*out == NULL))
    {
        len = i2d_X509((X509 *)cert_st, out);
        DBGPRINT(RT_DEBUG_TRACE, "%s: %d lines :out at %p\n", __func__, __LINE__, out);
    }
    else
    {


        unsigned char *p = *out;
        unsigned char len1 = 0;

        DBGPRINT(RT_DEBUG_TRACE, "%s: %d lines :len =%d\n", __func__, __LINE__, len);
        len1 = i2d_X509((X509 *)cert_st, NULL);

        if(len1>outlen)
        {
            return -1;
        }
        len = i2d_X509((X509 *)cert_st, &p);
    }

    DBGPRINT(RT_DEBUG_TRACE, "%s: %d lines :len =%d\n", __func__, __LINE__, len);
    return len;
}
static int X509_bincmp(void *a, void *b)
{
    struct cert_bin_t *cert_bin_a = a;
    struct cert_bin_t *cert_bin_b = b;
#if 0
    assert(cert_bin_a);
    assert(cert_bin_b);
#endif
    if(cert_bin_a == NULL ||cert_bin_b == NULL) return -3;
    if(cert_bin_a->length != cert_bin_b->length)
    {
        printf("length of certificates is  differently\n");
        return -1;
    }
    if(memcmp(cert_bin_a->data, cert_bin_b->data, cert_bin_a->length) != 0)
    {
        return -2;
    }

    return 0;
}

static void * X509_get_name_value(BUF_MEM *bytes)
{
    byte_data  *out;

    out = (byte_data *) get_buffer(sizeof(byte_data));
    if(out == NULL)
        return NULL;

    if(bytes->length>MAX_BYTE_DATA_LEN)
    {
        return NULL;
    }

    memcpy(out->data, bytes->data, bytes->length);
    out->length = bytes->length;
    return out;
}

static void *X509_wapi_get_subject_name(void *cert_st)
{
    X509 *x = (X509 *)cert_st;
    X509_NAME  *subject_name = NULL;
    BUF_MEM *bytes = NULL;

    subject_name=X509_get_subject_name(x);

    bytes = subject_name->bytes;

    return X509_get_name_value(bytes);
}

static void * X509_name_encode(X509_NAME *name)
{
    byte_data  *out;

    unsigned char *p = NULL;
    unsigned int len1 = 0;
    out = (byte_data *) get_buffer(sizeof(byte_data));
    if(out == NULL)
        return NULL;

    len1 = i2d_X509_NAME((X509_NAME *)name, NULL);

    if(len1>64)
    {
        return NULL;
    }
    p = out->data;
    out->length = i2d_X509_NAME((X509_NAME *)name, &p);
    return out;
}

void *X509_wapi_get_subject_name_vip(void *cert_st)
{
    X509 *x = (X509 *)cert_st;
    X509_NAME  *subject_name = NULL;

    subject_name=X509_get_subject_name(x);
    return X509_name_encode(subject_name);
}

static void *X509_wapi_get_issuer_name(void *cert_st)
{
    X509 *x = (X509 *)cert_st;
    X509_NAME  *issure_name = NULL;
    BUF_MEM *bytes = NULL;

    issure_name=X509_get_issuer_name(x);
    bytes = issure_name->bytes;
    return X509_get_name_value(bytes);
}

static void *X509_wapi_get_serial_number(void *cert_st)
{
    X509 *x = (X509 *)cert_st;
    ASN1_INTEGER *serial = NULL;

    byte_data *out = NULL;
    unsigned char *p = NULL;

    serial = X509_get_serialNumber(x);
    if(serial == NULL)
        return NULL;
    out = (byte_data *)get_buffer(sizeof(byte_data));
    if(out == NULL)
        return NULL;
    p = out->data;

    out->length = i2d_ASN1_INTEGER(serial, &p);
#if 0
    printf("\n------------dump serial der code begin ---------\n");
    print_string_array("x509: serial_number", out->data, out->length);
    printf("\n------------dump serial der code end ---------\n");
#endif
    return out;
}

tkey * x509_get_pubkey(X509 *x)
{
    EC_KEY *eckey = NULL;
    const EC_GROUP *group1;
    const EC_POINT *point;
    BIGNUM  *pubm=NULL;
    BN_CTX  *ctx=NULL;
    tkey *tpubkey = NULL;
    int tpubkeyl = sizeof(tkey);

    EVP_PKEY *pkey=NULL;

    if(x == NULL)
    {
        printf("in %s : %d x is NULL \n", __func__, __LINE__);
        return NULL;
    }

    pkey=X509_get_pubkey(x);

    if (pkey == NULL)
    {
        DPrintf("in %12s Unable to load Public Key\n",__func__);
        return NULL;
    }

    if (pkey->type == EVP_PKEY_EC)
    {
        DPrintf("%12s EC Public Key:\n", __func__);
        eckey = pkey->pkey.ec;
        //EC_KEY_print(bp, pkey->pkey.ec, 16);
    }
    else
    {
        DPrintf("in %12s Unknown Public Key:\n",__func__);
        goto error;
    }

    if ((group1 = EC_KEY_get0_group(eckey)) == NULL)
    {
        printf("in %s EC_KEY_get0_group failure\n", __func__);
        goto error;
    }

    point = EC_KEY_get0_public_key(eckey);
    if ((pubm = EC_POINT_point2bn(group1, point,
                                  EC_KEY_get_conv_form(eckey), NULL, ctx)) == NULL)
    {
        printf("in %s EC_POINT_point2bn failure\n", __func__);
        goto error;
    }
    tpubkey = (tkey *)get_buffer(tpubkeyl);

    if(tpubkey == NULL)
    {
        printf("in %s:%d get_buffer failure\n", __func__, __LINE__);
        goto error;
    }

    tpubkey->length = BN_bn2bin(pubm, tpubkey->data);
#if 0
    printf("\n-----------begin public key----------------------\n");
    print_string(pubkey->data, pubkey->length);
    printf("-----------end public key-------------------------\n");
#endif
exit:
    if (pubm)
        BN_free(pubm);
    if(pkey)
        EVP_PKEY_free(pkey);
    if (ctx)
        BN_CTX_free(ctx);
    return tpubkey;
error:
    if(tpubkey)
        tpubkey = free_buffer(tpubkey, tpubkeyl);
    goto exit;
}

static void *X509_wapi_get_pubkey(void *cert_st)
{
    X509 *x = (X509 *)cert_st;

    return x509_get_pubkey(x);
}

static struct cert_obj_st_t  cert_obj_x509 =
{
    .cert_type    = CERT_OBJ_X509,
    .cert_name = "x509v3",
    .asu_cert_st[0] = NULL,
    .asu_pubkey = NULL,
    .ca_cert_st = NULL,
    .ca_pubkey = NULL,
    .user_cert_st = NULL,
    .private_key    = NULL,
    .cert_bin   = NULL,

    .obj_new    = X509_wapi_new,
    .obj_free  = X509_obj_free,
    .decode = X509_decode,
    .encode = X509_encode,
    .cmp        = X509_bincmp,
    .get_public_key = X509_wapi_get_pubkey,
    .get_subject_name   = X509_wapi_get_subject_name,
    .get_issuer_name    = X509_wapi_get_issuer_name,
    .get_serial_number  = X509_wapi_get_serial_number,
    .verify_key = ecc192_verify_key,
    .sign   = ecc192_sign,
    .verify = ecc192_verify,
};

int X509_init()
{
    cert_obj_register(&cert_obj_x509);
    return 0;
}

void X509_exit()
{
    cert_obj_unregister(&cert_obj_x509);
}

