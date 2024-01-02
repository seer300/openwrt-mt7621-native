
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "ecc_crypt.h"
#include "structure.h"
#include "debug.h"

#if 1
void openssl_err(const char *func, int lines)
{
    const char *file_name = "";
    int line = 0;
    printf("in %s: %d print err\n", func, lines);
    ERR_get_error_line(&file_name, &line);
    printf("err at %s:%d\n", file_name, line);

}
#endif
static int print(BIO *bp, const char *number, const BIGNUM *num, unsigned char *buf,
                 int off)
{
    int n,i;
    const char *neg;

    if (num == NULL) return(1);
    neg = (BN_is_negative(num))?"-":"";
    if(!BIO_indent(bp,off,128))
        return 0;
    if (BN_is_zero(num))
    {
        if (BIO_printf(bp, "%s 0\n", number) <= 0)
            return 0;
        return 1;
    }

    if (BN_num_bytes(num) <= BN_BYTES)
    {
        if (BIO_printf(bp,"%s %s%lu (%s0x%lx)\n",number,neg,
                       (unsigned long)num->d[0],neg,(unsigned long)num->d[0])
            <= 0) return(0);
    }
    else
    {
        buf[0]=0;
        if (BIO_printf(bp,"%s%s",number,
                       (neg[0] == '-')?" (Negative)":"") <= 0)
            return(0);
        n=BN_bn2bin(num,&buf[1]);

        if (buf[1] & 0x80)
            n++;
        else    buf++;

        for (i=0; i<n; i++)
        {
            if ((i%15) == 0)
            {
                if(BIO_puts(bp,"\n") <= 0
                   || !BIO_indent(bp,off+4,128))
                    return 0;
            }
            if (BIO_printf(bp,"%02x%s",buf[i],((i+1) == n)?"":":")
                <= 0) return(0);
        }
        if (BIO_write(bp,"\n",1) <= 0) return(0);
    }
    return(1);
}

int EC_KEY_print_my(BIO *bp, const EC_KEY *x, int off)
{
    unsigned char *buffer=NULL;
    size_t  buf_len=0, i;
    int     ret=0, reason=ERR_R_BIO_LIB;
    BIGNUM  *pub_key=NULL, *order=NULL;
    BN_CTX  *ctx=NULL;
    const EC_GROUP *group;
    const EC_POINT *public_key = NULL;
    const BIGNUM *priv_key;

    if (x == NULL || (group = EC_KEY_get0_group(x)) == NULL)
    {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    public_key = EC_KEY_get0_public_key(x);

    if(public_key != NULL)
    {
        if ((pub_key = EC_POINT_point2bn(group, public_key,
                                         EC_KEY_get_conv_form(x), NULL, ctx)) == NULL)
        {
            reason = ERR_R_EC_LIB;
            goto err;
        }

        buf_len = (size_t)BN_num_bytes(pub_key);
    }
    priv_key = EC_KEY_get0_private_key(x);
    if (priv_key != NULL)
    {
        if ((i = (size_t)BN_num_bytes(priv_key)) > buf_len)
            buf_len = i;
    }

    buf_len += 10;
    if ((buffer = OPENSSL_malloc(buf_len)) == NULL)
    {
        reason = ERR_R_MALLOC_FAILURE;
        goto err;
    }

    if (priv_key != NULL)
    {
        if (!BIO_indent(bp, off, 128))
            goto err;
        if ((order = BN_new()) == NULL)
            goto err;
        if (!EC_GROUP_get_order(group, order, NULL))
            goto err;
        if (BIO_printf(bp, "Private-Key: (%d bit)\n",
                       BN_num_bits(order)) <= 0) goto err;
    }

    if ((priv_key != NULL) && !print(bp, "priv:", priv_key,
                                     buffer, off))
        goto err;
    if ((pub_key != NULL) && !print(bp, "pub: ", pub_key,
                                    buffer, off))
        goto err;
    if (!ECPKParameters_print(bp, group, off))
        goto err;
    ret=1;
err:
    if (!ret)
        ECerr(EC_F_EC_KEY_PRINT, reason);
    if (pub_key)
        BN_free(pub_key);
    if (order)
        BN_free(order);
    if (ctx)
        BN_CTX_free(ctx);
    if (buffer != NULL)
        OPENSSL_free(buffer);
    return(ret);
}

int EC_KEY_print_fp_my(FILE *fp, const EC_KEY *x, int off)
{
    BIO *b;
    int ret;

    if ((b=BIO_new(BIO_s_file())) == NULL)
    {
        ECerr(EC_F_EC_KEY_PRINT_FP, ERR_R_BIO_LIB);
        return(0);
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = EC_KEY_print_my(b, x, off);
    BIO_free(b);
    return(ret);
}


int point2bin(EC_KEY *eckey, unsigned char *pub_s , int pub_sl)
{
    const EC_POINT *point = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *group1;
    BIGNUM  *pubm=NULL;
    int ret = 0;

    if ((group1 = EC_KEY_get0_group(eckey)) == NULL)
    {
        goto error;
    }

    if ((pubm = EC_POINT_point2bn(group1, point,
                                  EC_KEY_get_conv_form(eckey), NULL, NULL)) == NULL)
    {
        goto error;
    }
    if(pub_sl > BN_num_bytes(pubm))
    {
        ret = BN_bn2bin(pubm, pub_s);
    }

error:
    if (pubm)
        BN_free(pubm);
    return ret;
}

static int set_point(EC_KEY *eckey, const unsigned char *pub_s, int pub_sl)
{

    EC_POINT *point = NULL;
    const EC_GROUP *group = NULL;
    int ret = 0;


    if((pub_s != NULL)
       &&(
           ((group = EC_KEY_get0_group(eckey)) != NULL)&&
           ((point = EC_POINT_new(group)) != NULL) &&
           (EC_POINT_oct2point(group, point, pub_s, pub_sl , NULL) != 0)))
    {
        EC_KEY_set_public_key(eckey, point);
        //DPrint_EC_KEY(stdout, eckey, 0);
    }
    else
    {
        ret = -1;
    }

    if(point)
        EC_POINT_free(point);
    return ret;
}

static int set_priv(EC_KEY *eckey, const unsigned char *priv_s, int priv_sl)
{
    BIGNUM *m = NULL;
    int ret = 0;


    if((priv_s != NULL)
       &&(
           ((m = BN_bin2bn(priv_s, priv_sl, NULL)) != NULL) && (EC_KEY_set_private_key(eckey, m) != 0)))
    {
        //DPrint_EC_KEY(stdout, eckey, 0);
        ;
    }
    else
    {
        ret = -1;
    }
    if(m)
        BN_free(m);
    return ret;
}

EC_KEY *geteckey_by_curve(int nid )
{
    EC_KEY *eckey = NULL;

    if ((eckey = EC_KEY_new_by_curve_name(nid)) == NULL)
    {
        //openssl_err(__func__, __LINE__);
        goto end;
    }
    if (!EC_KEY_generate_key(eckey))
        goto end;
    return eckey;
end:
    if(eckey)
    {
        EC_KEY_free(eckey);
    }
    return eckey;
}

EC_KEY * octkey2eckey(const unsigned char *pub_s, int pub_sl,
                      const unsigned char *priv_s, int priv_sl,   int nid)
{
    EC_KEY *eckey = NULL;

    if((pub_s == NULL) && (priv_s == NULL))
        return NULL;

    eckey = geteckey_by_curve(nid);

    if(eckey == NULL)
    {
        return NULL;
    }

    if((pub_s != NULL) && (set_point(eckey, pub_s, pub_sl) != 0))
    {
        goto err;
    }

    if((priv_s != NULL) && (set_priv(eckey, priv_s, priv_sl) != 0))
    {
        goto err;
    }

    return eckey;
err:
    if(eckey)
        EC_KEY_free(eckey);
    return NULL;
}

static ECDSA_SIG * bin2sign(EC_KEY  *eckey, const unsigned char *sign_s,int sign_sl)
{

    ECDSA_SIG *sign = NULL;
    eckey = eckey;

    sign = ECDSA_SIG_new();

    if(sign == NULL)
        return NULL;
    sign->r = BN_bin2bn(sign_s, sign_sl/2, sign->r);
    sign->s = BN_bin2bn(sign_s+sign_sl/2, sign_sl/2, sign->s);
    if ((sign->r == NULL) || (sign->s == NULL))
    {
        ECDSA_SIG_free(sign);
        sign = NULL;
    }
    return sign;
}

int sign2bin(EC_KEY  *eckey, ECDSA_SIG *s, unsigned char *signature,  int *siglen)
{
    eckey = eckey;

    BN_bn2bin(s->r, signature+24-BN_num_bytes(s->r));
    BN_bn2bin(s->s, signature+48-BN_num_bytes(s->s) );
    *siglen = 48;
    return 0;
}

static int openssl_ec_verify(EC_KEY  *eckey,
                             const unsigned char *message, int message_len,
                             const unsigned char *sign,int sign_l)
{
    EVP_MD_CTX md_ctx;
    unsigned char   digest[64];
    unsigned int    dgst_len = 0;
    int             ret =  0;

    ECDSA_SIG *s = NULL;

    EVP_MD_CTX_init(&md_ctx);
    /* get the message digest */
    EVP_DigestInit(&md_ctx, EVP_sha256());
    EVP_DigestUpdate(&md_ctx, (const void*)message, message_len);
    EVP_DigestFinal(&md_ctx, digest, &dgst_len);

    s = bin2sign(eckey, sign, sign_l);
    if(s == NULL)
    {
        goto  err;
    }
    if((ret = ECDSA_do_verify(digest, dgst_len, s, eckey)) != 1)
    {
        openssl_err(__func__, __LINE__);
    }
err:
    EVP_MD_CTX_cleanup(&md_ctx);
    if(s != NULL)
        ECDSA_SIG_free(s);
    return ret;
}

int ECDSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char
               *sig, unsigned int *siglen, EC_KEY *eckey);

static int openssl_ec_sign(EC_KEY  *eckey,
                           const unsigned char *message, int message_len,
                           unsigned char *signature,int *sign_len)
{
    int             ret =  1;
    unsigned char   digest[64];
    unsigned int    dgst_len = 0;
    ECDSA_SIG *s = NULL;
    EVP_MD_CTX md_ctx;

    EVP_MD_CTX_init(&md_ctx);
    /* get the message digest */
    EVP_DigestInit(&md_ctx, EVP_sha256());
    EVP_DigestUpdate(&md_ctx, (const void*)message, message_len);
    EVP_DigestFinal(&md_ctx, digest, &dgst_len);

    s = ECDSA_do_sign_ex(digest, dgst_len, NULL, NULL, eckey);
    if (s == NULL)
    {
        openssl_err(__func__, __LINE__);
        *sign_len=0;
        goto err;
    }
    sign2bin(eckey, s, signature, sign_len);
    ret = 0;
err:
    if(s != NULL)
        ECDSA_SIG_free(s);
    EVP_MD_CTX_cleanup(&md_ctx);
    return ret;
}
int   ecc192_verify(const unsigned char *pub_s, int pub_sl, unsigned char *in ,  int in_len, unsigned char *sig,int sign_len)
{
    EC_KEY *eckey = NULL;
    int ret = 0;

    eckey = octkey2eckey(pub_s, pub_sl, NULL, 0, NID_X9_62_prime192v1);


    if(eckey == NULL)
    {
        goto err;
    }

    ret = openssl_ec_verify(eckey, in, in_len, sig,  sign_len);

    if(eckey)
        EC_KEY_free(eckey);
err:
    return ret;
}

int ecc192_sign(const unsigned char *priv_s, int priv_sl,
                const unsigned char * in, int in_len,
                unsigned char *out)
{
    EC_KEY *eckey = NULL;
    int outl = 0;

    eckey = octkey2eckey(NULL, 0, priv_s, priv_sl, NID_X9_62_prime192v1);

    if(eckey == NULL)
    {
        return 0;
    }

    if(openssl_ec_sign(eckey, in, in_len, out, &outl) != 0)
    {
        outl = 0;
    }

    if(eckey)
        EC_KEY_free(eckey);

    return outl;
}


int ecc192_ecdh(const unsigned char *apub_s, int apub_sl,
                const unsigned char *bpriv_s, int bpriv_sl,
                const unsigned char *bpub_s, int bpub_sl,
                unsigned char *key, int keyl)
{
    EC_KEY *eckeya = NULL;
    EC_KEY *eckeyb = NULL;
    int ret = 0;


    eckeya = octkey2eckey(apub_s, apub_sl, NULL, 0, NID_X9_62_prime192v1);
    eckeyb = octkey2eckey(bpub_s, bpub_sl, bpriv_s, bpriv_sl, NID_X9_62_prime192v1);

    if((eckeya == NULL) || (eckeyb == NULL))
    {
        goto err;
    }

    ret = ECDH_compute_key(key, keyl,EC_KEY_get0_public_key(eckeya), eckeyb, NULL);

err:
    if(eckeya)
        EC_KEY_free(eckeya);
    if(eckeyb)
        EC_KEY_free(eckeyb);
    return ret;
}
#if 0
void check_key(const unsigned char *pub_s, int pub_sl,
               const unsigned char *priv_s, int priv_sl);
#endif
int ecc192_verify_key(const unsigned char *pub_s, int pub_sl,
                      const unsigned char *priv_s, int priv_sl)
{
    EC_KEY *eckey = NULL;
    int ret = 1;

    eckey = octkey2eckey(pub_s, pub_sl, priv_s, priv_sl,  NID_X9_62_prime192v1);

    if((eckey == NULL) ||  (!EC_KEY_check_key(eckey)))
    {
        ret = 0;
    }
    return ret;
}
#if 0
void check_key(const unsigned char *pub_s, int pub_sl,
               const unsigned char *priv_s, int priv_sl)
{
    unsigned char data[4]= {0x01, 0x02, 0x03, 0x04};
    unsigned char sign[128] = {0,};
    int signl = 0;

    EC_KEY *eckey = octkey2eckey(pub_s, pub_sl, priv_s, priv_sl,  NID_X9_62_prime192v1);

    DPrint_EC_KEY(stdout, eckey, 0);
    if(eckey != NULL)
    {
        if(openssl_ec_sign(eckey, data, 4, sign, &signl))
        {
            abort();
        }
        if(openssl_ec_verify(eckey, data, 4, sign, signl) != 1)
        {
            abort();
        }
        signl = ecc192_sign(priv_s, priv_sl, data, 4, sign);
        if(ecc192_verify(pub_s, pub_sl, data, 4, sign, signl) == 0)
        {
            abort();
        }
    }
}
#endif
EC_KEY * ecc192_generate_eckey_ssl(unsigned  int curve_id  )
{
    EC_KEY *eckey = NULL;

    eckey = geteckey_by_curve(curve_id );
    if(eckey == NULL)
        return NULL;
#if 0
    if (!EC_KEY_generate_key(eckey))
        return NULL;
#endif
    DPrint_EC_KEY(stdout, eckey, 0);

    return eckey;
}
int eckey2octkey(const EC_KEY *eckey, tkey *pub_s, tkey *priv_s)
{
    const BIGNUM *priv_key = NULL;
    const EC_GROUP *group1 = NULL;
    const EC_POINT *pub_point = NULL;
    BIGNUM  *pub_key=NULL;
    BN_CTX  *ctx=NULL;
    int ret = 0;

    priv_key = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);

    if((priv_key == NULL) || (pub_point == NULL))
    {
        return -1;
    }
    if ((group1 = EC_KEY_get0_group(eckey)) == NULL)
    {
        printf("in %s EC_KEY_get0_group failure\n", __func__);
        ret = -1;
        goto error;
    }
    if ((pub_key = EC_POINT_point2bn(group1, pub_point,
                                     EC_KEY_get_conv_form(eckey), NULL, ctx)) == NULL)
    {
        printf("in %s EC_POINT_point2bn failure\n", __func__);
        ret = -1;
        goto error;
    }

    priv_s->length = BN_bn2bin(priv_key, priv_s->data+24-BN_num_bytes(priv_key));
    pub_s->length = BN_bn2bin(pub_key, pub_s->data);
    pub_s->length  -= 1;
    memmove(pub_s->data, pub_s->data+1, pub_s->length );
error:
    if (pub_key)
        BN_free(pub_key);
    if (ctx)
        BN_CTX_free(ctx);
    return ret;
}

int ecc192_generate_octkey_ssl(unsigned  int curve_id ,tkey *pub_s, tkey *priv_s)
{
    int ret = 0;
    EC_KEY *eckey = NULL;

    eckey = ecc192_generate_eckey_ssl(curve_id);

    if(eckey == NULL)
        return -1;
    ret = eckey2octkey(eckey, pub_s, priv_s);

    EC_KEY_free(eckey);
    return ret;
}
