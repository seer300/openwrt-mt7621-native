
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "openssl/ec.h"
#include "openssl/obj_mac.h"

#include "cert_auth.h"
#include "proc.h"
#include "type_def.h"
#include "pack.h"
#include "debug.h"
#include "alg_comm.h"
#include "structure.h"
//#include "cert_auth.h"
#include "ecc_crypt.h"
#include "wapi.h"

#include <sys/types.h>
#include <sys/socket.h>

//static const UCHAR    Input_text[100] = "multicast or station key expansion for station unicast and multicast and broadcast";

static INT wai_fixdata_cert_by_certificate(const struct cert_obj_st_t *cert_obj,
        wai_fixdata_cert *fixdata_cert,
        USHORT index);

static INT wai_fixdata_cert_by_certificate(const struct cert_obj_st_t *cert_obj,
        wai_fixdata_cert *fixdata_cert,
        USHORT index)
{
    if((fixdata_cert==NULL)||(cert_obj == NULL)) return -1;
    fixdata_cert->cert_flag =index; /*GBW*/
    fixdata_cert->cert_bin.data = cert_obj->cert_bin->data;
    fixdata_cert->cert_bin.length = cert_obj->cert_bin->length;

    return 0;

}

INT wai_initialize_ecdh(para_alg *ecdh)
{
    CHAR alg_para_oid_der[16] = {0x06, 0x09,0x2a,0x81,0x1c, 0xd7,0x63,0x01,0x01,0x02,0x01};

    memset((UCHAR *)ecdh, 0, sizeof(para_alg));
    ecdh->para_flag= 1;
    ecdh->para_len = 11;
    memcpy(ecdh->para_data, alg_para_oid_der, 11);
    return 0;
}

INT wai_copy_ecdh(para_alg *ecdh_a, para_alg *ecdh_b)
{
    memset((UCHAR *)ecdh_a, 0, sizeof(para_alg));

    ecdh_a->para_flag = ecdh_b->para_flag;
    ecdh_a->para_len = ecdh_b->para_len;
    memcpy(ecdh_a->para_data, ecdh_b->para_data, ecdh_b->para_len);
    return 0;
}

INT wai_compare_ecdh(para_alg *ecdh_a, para_alg *ecdh_b)
{
    if(ecdh_a == NULL || ecdh_b == NULL)
    {
        return -1;
    }
    else if((ecdh_a->para_flag!= ecdh_b->para_flag) ||
            (ecdh_a->para_len !=  ecdh_b->para_len)||
            (memcmp(ecdh_a->para_data, ecdh_b->para_data,  ecdh_b->para_len)!=0))
    {
        return -1;
    }
    return 0;
}

INT wai_fixdata_id_by_ident(void *cert_st,
                            wai_fixdata_id *fixdata_id,
                            USHORT index)
{
    UCHAR *temp ;
    byte_data       *subject_name = NULL;
    byte_data       *issure_name = NULL;
    byte_data       *serial_no = NULL;
    const struct cert_obj_st_t *cert_obj = NULL;

    if(fixdata_id == NULL) return -1;
    temp= fixdata_id->id_data;
    fixdata_id->id_flag = index;
    /*according to the index, can call external objs if want to process asue id at the
    same time*/
    if(cert_st == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "cert_st is NULL\n");
        return -1;
    }
    cert_obj = get_cert_obj(index);
    if((cert_obj == NULL)
       ||(cert_obj->obj_new == NULL)
       ||(cert_obj->obj_free == NULL)
       ||(cert_obj->decode == NULL)
       ||(cert_obj->encode == NULL)
       ||(cert_obj->cmp == NULL)
       ||(cert_obj->get_public_key == NULL)
       ||(cert_obj->get_subject_name == NULL)
       ||(cert_obj->get_issuer_name == NULL)
       ||(cert_obj->get_serial_number == NULL)
       ||(cert_obj->verify_key == NULL)
       ||(cert_obj->sign == NULL)
       ||(cert_obj->verify == NULL))
    {
        DBGPRINT(RT_DEBUG_ERROR, "Not found cert_obj\n");
        return -4;
    }
    subject_name = (*cert_obj->get_subject_name)(cert_st);
    issure_name = (*cert_obj->get_issuer_name)(cert_st);
    serial_no = (*cert_obj->get_serial_number)(cert_st);

    if((subject_name == NULL) || (issure_name == NULL) || (serial_no == NULL))
        /*
                || subject_name->length > MAX_BYTE_DATA_LEN
                || issure_name->length > MAX_BYTE_DATA_LEN
                || serial_no->length > MAX_BYTE_DATA_LEN )
        */
    {
        return -2;
    }

    memcpy(temp, subject_name->data, subject_name->length);
    temp += subject_name->length;

    memcpy(temp, issure_name->data, issure_name->length);
    temp += issure_name->length;

    memcpy(temp, serial_no->data, serial_no->length);
    temp +=serial_no->length;

    fixdata_id->id_len = temp - fixdata_id->id_data;
    free_buffer(subject_name,sizeof(byte_data));
    free_buffer(issure_name,sizeof(byte_data));
    free_buffer(serial_no,sizeof(byte_data));
    return 0;
}

SHORT pack_auth_active(
    auth_active* pContent,
    PUCHAR buffer,
    USHORT *buffer_len,
    USHORT bufflen)
{
    USHORT offset= *buffer_len;

    offset = c_pack_word(&pContent->asu_id.id_flag,buffer,offset,bufflen);
    offset = c_pack_word(&pContent->asu_id.id_len,buffer,offset,bufflen);
    memcpy(buffer + offset, &pContent->asu_id.id_data, pContent->asu_id.id_len);
    offset +=   pContent->asu_id.id_len;

    offset = c_pack_word(&pContent->ae_cer.cert_flag,buffer,offset,bufflen);
    offset = c_pack_word(&pContent->ae_cer.cert_bin.length,buffer,offset,bufflen);
    memcpy((buffer + offset), pContent->ae_cer.cert_bin.data, pContent->ae_cer.cert_bin.length);
    offset += pContent->ae_cer.cert_bin.length;

    offset = c_pack_byte((UCHAR *)&pContent->ecdh.para_flag,buffer,offset,bufflen);

    ((unsigned char *)buffer)[offset]= (pContent->ecdh.para_len >> 8)&0xff;
    offset += 1;
    ((unsigned char *)buffer)[offset]= (pContent->ecdh.para_len&0xff) ;
    offset += 1;

    memcpy(buffer + offset, pContent->ecdh.para_data, pContent->ecdh.para_len);
    offset += pContent->ecdh.para_len;

    return offset;
}

SHORT pack_access_auth_request(
    PRTMP_ADAPTER pAd,
    const access_auth_request* pContent,
    PUCHAR buffer,
    USHORT buffer_len,
    USHORT bufflen)
{
    USHORT offset= buffer_len;
    USHORT sign_len_pos = 0;
    USHORT sign_val_len = 48;
    big_data data_buff;
    tsign   sign;

    offset = c_pack_byte_data(&pContent->key_data,buffer,offset,bufflen);
    offset = c_pack_word(&pContent->ae_id.id_flag,buffer,offset,bufflen);
    offset = c_pack_word(&pContent->ae_id.id_len,buffer,offset,bufflen);
    memcpy(buffer + offset, &pContent->ae_id.id_data, pContent->ae_id.id_len);
    offset += pContent->ae_id.id_len;
    offset = c_pack_word(&pContent->asue_cert.cert_flag,buffer,offset,bufflen);
    offset = c_pack_word(&pContent->asue_cert.cert_bin.length,buffer,offset,bufflen);
    memcpy(buffer + offset, pContent->asue_cert.cert_bin.data, pContent->asue_cert.cert_bin.length);
    offset += pContent->asue_cert.cert_bin.length;

    offset = c_pack_byte((UCHAR *)&pContent->ecdh.para_flag,buffer,offset,bufflen);
    ((unsigned char *)buffer)[offset]= (pContent->ecdh.para_len >> 8)&0xff;
    offset += 1;
    ((unsigned char *)buffer)[offset]= (pContent->ecdh.para_len&0xff) ;
    offset += 1;
    memcpy(buffer + offset, pContent->ecdh.para_data, pContent->ecdh.para_len);
    offset += pContent->ecdh.para_len;

    if (pContent->asu_id_list.identifier == ID_LIST)
    {
        INT idx;

        offset = c_pack_byte(&(pContent->asu_id_list.identifier), buffer, offset,bufflen);
        offset = c_pack_word(&(pContent->asu_id_list.length), buffer,offset,bufflen);
        offset = c_pack_byte(&(pContent->asu_id_list.rev), buffer, offset,bufflen);
        offset = c_pack_word(&(pContent->asu_id_list.id_no), buffer,offset,bufflen);

        for (idx=0; idx<pContent->asu_id_list.id_no; idx++)
        {
            offset = c_pack_word(&(pContent->asu_id_list.id[idx].id_flag), buffer,offset,bufflen);
            offset = c_pack_word(&(pContent->asu_id_list.id[idx].id_len), buffer,offset,bufflen);
            offset = c_pack_nbytes(&(pContent->asu_id_list.id[idx].id_data),
                                   pContent->asu_id_list.id[idx].id_len, buffer,
                                   offset,bufflen);
        }
    }

    data_buff.length = offset;
    memcpy(data_buff.data, buffer, data_buff.length);

    sign.length = (*pAd->cert_info.local_cert_obj->sign)(
                      pAd->cert_info.local_cert_obj->private_key->data,
                      pAd->cert_info.local_cert_obj->private_key->length,
                      data_buff.data,     data_buff.length, sign.data);

    assert(sign.length != 0);
    if(sign.length == 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "err in %s:%d\n", __func__, __LINE__);
        return -1;
    }

    *(buffer + offset) = 1;
    offset += 1;
    sign_len_pos = offset;
    offset += 2;

    offset = c_pack_word(&pAd->local_user_id.id_flag,buffer,offset,bufflen);
    offset = c_pack_word(&pAd->local_user_id.id_len,buffer,offset,bufflen);
    memcpy(buffer + offset, &pAd->local_user_id.id_data, pAd->local_user_id.id_len);
    offset += pAd->local_user_id.id_len;

    offset = c_pack_sign_alg(&pAd->sign_alg, buffer,offset,bufflen);
    offset = c_pack_word((UINT16 *)&sign_val_len,buffer,offset,bufflen);

    memcpy(buffer + offset, sign.data, 48);
    offset += 48;

    buffer[sign_len_pos] = ((offset - sign_len_pos - 2)>>8)&0xff;
    buffer[sign_len_pos+1] = ((offset - sign_len_pos - 2))&0xff;

    return offset;
}

SHORT pack_certificate_auth_request(
    PRTMP_ADAPTER pAd,
    const access_auth_request *pContent,
    void* buffer,
    USHORT buffer_len,
    USHORT bufflen)
{
    USHORT offset = buffer_len;
    struct cert_obj_st_t *ap_cert_obj ;

    ap_cert_obj = pAd->cert_info.local_cert_obj;

    /*ASUE certificate*/
    offset = c_pack_word(&pContent->asue_cert.cert_flag,buffer ,offset,bufflen);
    offset = c_pack_word(&pContent->asue_cert.cert_bin.length,buffer ,offset,bufflen);
    memcpy(buffer + offset, pContent->asue_cert.cert_bin.data, pContent->asue_cert.cert_bin.length);
    offset += pContent->asue_cert.cert_bin.length;

    /*AE certificate*/
    printf("process_accessrequest:cert_index=%d\n",pAd->cert_info.config.used_cert);
    offset = c_pack_word(&pAd->cert_info.config.used_cert, buffer ,offset,bufflen);
    offset = c_pack_word(&ap_cert_obj->cert_bin->length,buffer,offset,bufflen);
    memcpy(buffer + offset, ap_cert_obj->cert_bin->data, ap_cert_obj->cert_bin->length);
    offset += pAd->cert_info.local_cert_obj->cert_bin->length;

    if (pContent->asu_id_list.identifier == ID_LIST)
    {
        INT idx;
#if 0
        printf("push asue trust lists\n");
        memcpy(buffer + offset, (UCHAR *)&(pContent->asu_id_list), pContent->asu_id_list.id_no * 4 + 6);
        offset += pContent->asu_id_list.id_no * 4 + 6;
#endif

        offset = c_pack_byte(&(pContent->asu_id_list.identifier), buffer, offset,bufflen);
        offset = c_pack_word(&(pContent->asu_id_list.length), buffer,offset,bufflen);
        offset = c_pack_byte(&(pContent->asu_id_list.rev), buffer, offset,bufflen);
        offset = c_pack_word(&(pContent->asu_id_list.id_no), buffer,offset,bufflen);

        for (idx=0; idx<pContent->asu_id_list.id_no; idx++)
        {
            offset = c_pack_word(&(pContent->asu_id_list.id[idx].id_flag), buffer,offset,bufflen);
            offset = c_pack_word(&(pContent->asu_id_list.id[idx].id_len), buffer,offset,bufflen);
            offset = c_pack_nbytes(&(pContent->asu_id_list.id[idx].id_data),
                                   pContent->asu_id_list.id[idx].id_len, buffer,
                                   offset,bufflen);
        }
    }

    assert(offset !=PACK_ERROR);

    return 0;
}


USHORT wapi_auth_activate_create(
    IN  PRTMP_ADAPTER   pAd,
    IN  PUCHAR  pAddr,
    IN  PUCHAR  sendto_asue)
{
    STA_TABLE_ENTRY  *pEntry = NULL;
    auth_active auth_active_info;
    USHORT  sendto_asue_total_len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_auth_activate_create\n");

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "STA " MACSTR " doesn't exist in the sta table \n", MAC2STR(pAddr));
        return -1;
    }

    memset(&auth_active_info, 0, sizeof(auth_active));

    /* get asu id from asu certificate */
    if (wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->asu_cert_st[0],
                                &(auth_active_info.asu_id),
                                pAd->cert_info.config.used_cert)!=0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_auth_activate_create -- wai_fixdata_id_by_ident fail\n");
        return 0;
    }

    /* get local user cert certificate */
    if (wai_fixdata_cert_by_certificate(pAd->cert_info.local_cert_obj,
                                        &(auth_active_info.ae_cer),
                                        pAd->cert_info.config.used_cert) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_auth_activate_create -- wai_fixdata_cert_by_certificate fail\n");
        return 0;
    }

    wai_initialize_ecdh(&auth_active_info.ecdh);

    sendto_asue_total_len = c_pack_byte((UINT8 *)&pEntry->id_flag,sendto_asue,sendto_asue_total_len,MAX_WAI_AUTH_HS_LEN);
    sendto_asue_total_len = c_pack_32bytes((UINT8 *)&pEntry->AUTH_ID,sendto_asue,sendto_asue_total_len,MAX_WAI_AUTH_HS_LEN);
    sendto_asue_total_len = pack_auth_active(&auth_active_info, sendto_asue, &sendto_asue_total_len, MAX_WAI_AUTH_HS_LEN);

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_auth_activate_create\n");
    return sendto_asue_total_len;
}

SHORT wapi_auth_activate_check(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   recvfrom_ae,
    IN USHORT   recvfrom_ae_len)
{
    STA_TABLE_ENTRY  *pEntry = NULL;
    auth_active auth_active_info;
    USHORT offset = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_auth_activate_check\n");

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    // If the STA doesn't exist, insert it to table
    if (pEntry == NULL)
    {
        return PACK_ERROR;
    }

    offset = unpack_ae_auth_active(&auth_active_info, recvfrom_ae,  recvfrom_ae_len);
    if (offset==PACK_ERROR)
    {
        return PACK_ERROR;
    }

    pEntry->user_cert.cert_flag = auth_active_info.ae_cer.cert_flag;
    pEntry->user_cert.cert_len = auth_active_info.ae_cer.cert_bin.length;
    memcpy(pEntry->user_cert.cert_data, auth_active_info.ae_cer.cert_bin.data, auth_active_info.ae_cer.cert_bin.length);

    wai_copy_ecdh(&pEntry->ecdh,&auth_active_info.ecdh);

    pEntry->asu_id.id_flag = auth_active_info.asu_id.id_flag;
    pEntry->asu_id.id_len = auth_active_info.asu_id.id_len;
    memcpy(&pEntry->asu_id.id_data, &auth_active_info.asu_id.id_data, auth_active_info.asu_id.id_len);

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_auth_activate_check\n");

    return 0;
}

USHORT wapi_access_auth_request_create(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   sendto_ae)
{
    access_auth_request sta_auth_requ;
    EC_KEY  *asue_eck = NULL;
    STA_TABLE_ENTRY  *pEntry = NULL;
    void *ae_cert = NULL;
    const struct cert_obj_st_t  *cert_obj = NULL;
    USHORT  cert_type;
    const BIGNUM *priv_key;
    USHORT sendto_ae_len = 0;
    SHORT   sendto_ae_total_len = 0;
    INT idx;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_access_auth_request_create\n");

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_TRACE, " Not find STA\n");
        return -1;
    }

    memset(&sta_auth_requ, 0, sizeof(access_auth_request));

    asue_eck = geteckey_by_curve(NID_X9_62_prime192v1);

    if(asue_eck == NULL)
    {
        goto err;
    }
    else if (!EC_KEY_generate_key(asue_eck))
    {
        goto err;
    }

    memset(&pEntry->private_key, 0, sizeof(tkey));
    priv_key = EC_KEY_get0_private_key(asue_eck);

    if(priv_key != NULL)
    {
        pEntry->private_key.length = BN_bn2bin(priv_key, pEntry->private_key.data);
    }

    sta_auth_requ.key_data.length = point2bin(asue_eck, (UINT8*)(&sta_auth_requ.key_data.data), MAX_BYTE_DATA_LEN);
    memcpy(pEntry->asue_key_data.data, sta_auth_requ.key_data.data, sta_auth_requ.key_data.length);
    pEntry->asue_key_data.length = sta_auth_requ.key_data.length;

    cert_type = pEntry->user_cert.cert_flag;
    cert_obj = get_cert_obj(cert_type);

    if((cert_obj == NULL)
       ||(cert_obj->obj_new == NULL)
       ||(cert_obj->obj_free == NULL)
       ||(cert_obj->decode == NULL)
       ||(cert_obj->encode == NULL)
       ||(cert_obj->cmp == NULL)
       ||(cert_obj->get_public_key == NULL)
       ||(cert_obj->get_subject_name == NULL)
       ||(cert_obj->get_issuer_name == NULL)
       ||(cert_obj->get_serial_number == NULL)
       ||(cert_obj->verify_key == NULL)
       ||(cert_obj->sign == NULL)
       ||(cert_obj->verify == NULL))
    {
        printf("Not found cert_obj\n");
        return -1;
    }

    /* X509 decode */
    (*cert_obj->decode)(&ae_cert, pEntry->user_cert.cert_data, pEntry->user_cert.cert_len);

    wai_fixdata_id_by_ident(ae_cert, &(sta_auth_requ.ae_id),cert_type);

    if (wai_fixdata_cert_by_certificate(pAd->cert_info.local_cert_obj,
                                        &(sta_auth_requ.asue_cert),
                                        pAd->cert_info.config.used_cert) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_access_auth_request_create -- wai_fixdata_cert_by_certificate fail\n");
        goto err;
    }

    wai_initialize_ecdh(&sta_auth_requ.ecdh);

    /* get asu id from asu certificate */
    if (pAd->cert_info.config.cert_mode == THREE_CERTIFICATE_MODE)
    {
        for(idx=0; idx<pAd->cert_info.config.as_no; idx++)
        {
            if (wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->asu_cert_st[idx],
                                        &(sta_auth_requ.asu_id_list.id[idx]),
                                        pAd->cert_info.config.used_cert)!=0)
            {
                DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_create -- wai_fixdata_id_by_ident fail\n");
                goto err;
            }
            sta_auth_requ.asu_id_list.length += sta_auth_requ.asu_id_list.id[idx].id_len + 4; // id_flag(2) + id_len(2)
        }

        pEntry->id_flag |= WAI_FLAG_OPTION;
        sta_auth_requ.asu_id_list.identifier = ID_LIST;
        sta_auth_requ.asu_id_list.length += 3;  //rev(1) + id_no(2)
        sta_auth_requ.asu_id_list.rev = 0;
        sta_auth_requ.asu_id_list.id_no = pAd->cert_info.config.as_no;
    }

    sendto_ae_total_len = c_pack_byte((UINT8 *)&pEntry->id_flag,sendto_ae,sendto_ae_total_len,MAX_WAI_AUTH_HS_LEN);
    if (sendto_ae_total_len == -1)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_create -- pack id_flag fail\n");
        goto err;
    }
    sendto_ae_total_len = c_pack_32bytes((UINT8 *)&pEntry->AUTH_ID,sendto_ae,sendto_ae_total_len,MAX_WAI_AUTH_HS_LEN);
    if (sendto_ae_total_len == -1)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_create -- pack AUTH_ID fail\n");
        goto err;
    }
    sendto_ae_total_len = c_pack_32bytes((UINT8 *)&pEntry->SNONCE,sendto_ae,sendto_ae_total_len,MAX_WAI_AUTH_HS_LEN);

    sendto_ae_total_len = pack_access_auth_request(pAd, &sta_auth_requ, sendto_ae, sendto_ae_total_len, FROM_MT_LEN);
    if (sendto_ae_total_len == -1)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_create -- pack_access_auth_request fail\n");
        goto err;
    }
    else
    {
        sendto_ae_len = sendto_ae_total_len;
    }

err:
    if(asue_eck)
        EC_KEY_free(asue_eck);

    if(ae_cert != NULL)
    {
        (*cert_obj->obj_free)(&ae_cert);
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_access_auth_request_create\n");

    if (sendto_ae_total_len == -1)
        return 0;
    else
        return sendto_ae_len;
}

SHORT wapi_access_auth_request_check(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   recvfrom_asue,
    IN USHORT   recvfrom_asue_len)
{
    STA_TABLE_ENTRY  *pEntry = NULL;
    USHORT      no_signdata_len = 0;
    USHORT      offset_mt=0;
    USHORT      cert_type;
    big_data    data_buff;
    access_auth_request sta_auth_requ;
    tsign       sign;
    tkey        *pubkey = NULL;
    void        *asue_cert = NULL;
    const struct cert_obj_st_t  *cert_obj = NULL;
    INT res = 0;
    INT ret = 0;
    INT idx;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_access_auth_request_check\n");

    if((recvfrom_asue == NULL)|| (pAddr == NULL)||(recvfrom_asue_len < 12)) return -1;

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "STA " MACSTR " doesn't exist in the sta table \n", MAC2STR(pAddr));
        ret = -1;
        goto errexit;
    }

    memset(&sta_auth_requ, 0, sizeof(access_auth_request));
    memset(&data_buff, 0, sizeof(big_data));
    memset(&sign, 0, sizeof(tsign));

    offset_mt = unpack_access_auth_request(&sta_auth_requ, recvfrom_asue,  recvfrom_asue_len, &no_signdata_len);

    if( offset_mt == PACK_ERROR )
    {
        DBGPRINT(RT_DEBUG_ERROR, "unpack_auth_request error\n");
        ret = -1;
        goto errexit;
    }

    if(memcmp((UCHAR *)&(sta_auth_requ.ae_id), (UCHAR *)&(pAd->local_user_id), pAd->local_user_id.id_len + 4) !=0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "ae id is not same,id len =%d\n",pAd->local_user_id.id_len);
        DBGPRINT(RT_DEBUG_ERROR, "current ae id\n ");
        hex_dump("current ae id", (UCHAR *)&(sta_auth_requ.ae_id), pAd->local_user_id.id_len + 4);
        DBGPRINT(RT_DEBUG_ERROR, "saved ae id\n ");
        hex_dump("saved ae id", (UCHAR *)&(pAd->local_user_id), pAd->local_user_id.id_len + 4);

        ret = -1;
        goto errexit;
    }

    if(wai_compare_ecdh(&sta_auth_requ.ecdh, &pAd->local_ecdh)!=0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "ecdh is not same\n");
        DBGPRINT(RT_DEBUG_ERROR, "current ecdh\n");
        hex_dump("current ecdh", (UCHAR *)&pAd->local_ecdh, pAd->local_ecdh.para_len + 3);
        DBGPRINT(RT_DEBUG_ERROR, "saved ecdh\n");
        hex_dump("saved ecdh", (UCHAR *)&(pAd->local_ecdh), pAd->local_ecdh.para_len + 3);

        ret = -1;
        goto errexit;
    }

    data_buff.length = no_signdata_len;
    memcpy(data_buff.data, recvfrom_asue, data_buff.length);

    cert_type = sta_auth_requ.asue_cert.cert_flag;
    if(cert_type != 1)
    {
        DBGPRINT(RT_DEBUG_ERROR, "none X509 certificate\n");

        ret = -2;
        goto errexit;
    }

    cert_obj = get_cert_obj(cert_type);

    if((cert_obj == NULL)
       ||(cert_obj->obj_new == NULL)
       ||(cert_obj->obj_free == NULL)
       ||(cert_obj->decode == NULL)
       ||(cert_obj->encode == NULL)
       ||(cert_obj->cmp == NULL)
       ||(cert_obj->get_public_key == NULL)
       ||(cert_obj->get_subject_name == NULL)
       ||(cert_obj->get_issuer_name == NULL)
       ||(cert_obj->get_serial_number == NULL)
       ||(cert_obj->verify_key == NULL)
       ||(cert_obj->sign == NULL)
       ||(cert_obj->verify == NULL))
    {
        DBGPRINT(RT_DEBUG_ERROR, "Not found cert_obj\n");
        ret = -4;
        goto errexit;
    }

    (*cert_obj->decode)(&asue_cert, sta_auth_requ.asue_cert.cert_bin.data, sta_auth_requ.asue_cert.cert_bin.length);

    pubkey = (*cert_obj->get_public_key)(asue_cert);

    res = (*cert_obj->verify)(pubkey->data, pubkey->length,
                              data_buff.data,data_buff.length,
                              sta_auth_requ.asue_sign.sign_data.data,
                              sta_auth_requ.asue_sign.sign_data.length);
    if(!res)
    {
        DBGPRINT(RT_DEBUG_ERROR, "\nAE verify ASUE sign  error!!!,res = %d\n\n",res);
        ret = -1;
        goto errexit;
    }

    pEntry->user_cert.cert_flag = sta_auth_requ.asue_cert.cert_flag;
    pEntry->user_cert.cert_len = sta_auth_requ.asue_cert.cert_bin.length;
    memcpy(pEntry->user_cert.cert_data, sta_auth_requ.asue_cert.cert_bin.data, sta_auth_requ.asue_cert.cert_bin.length);

    memcpy(pEntry->SNONCE , sta_auth_requ.asue_challenge, 32);
    memcpy(pEntry->asue_key_data.data, sta_auth_requ.key_data.data, sta_auth_requ.key_data.length);
    pEntry->asue_key_data.length = sta_auth_requ.key_data.length;

    pEntry->asu_id_list.identifier = sta_auth_requ.asu_id_list.identifier;
    pEntry->asu_id_list.length = sta_auth_requ.asu_id_list.length;
    pEntry->asu_id_list.id_no = sta_auth_requ.asu_id_list.id_no;
    pEntry->asu_id_list.rev = sta_auth_requ.asu_id_list.rev;

    for(idx=0; idx<pEntry->asu_id_list.id_no; idx++)
    {
        pEntry->asu_id_list.id[idx].id_flag = sta_auth_requ.asu_id_list.id[idx].id_flag;
        pEntry->asu_id_list.id[idx].id_len = sta_auth_requ.asu_id_list.id[idx].id_len;
        memcpy(pEntry->asu_id_list.id[idx].id_data, sta_auth_requ.asu_id_list.id[idx].id_data, sta_auth_requ.asu_id_list.id[idx].id_len);
    }

    wai_fixdata_id_by_ident(asue_cert, &(pEntry->user_id),cert_type);

    mhash_sha256(sta_auth_requ.asue_cert.cert_bin.data,
                 sta_auth_requ.asue_cert.cert_bin.length,
                 pEntry->asue_cert_hash);

errexit:

    if(pubkey != NULL)
    {
        pubkey = free_buffer(pubkey, sizeof(tkey));
    }
    if(asue_cert != NULL)
    {
        (*cert_obj->obj_free)(&asue_cert);
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_access_auth_request_check\n");

    return 0;
}

USHORT wapi_certificate_auth_request_create(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   sendto_as)
{
    STA_TABLE_ENTRY  *pEntry = NULL;
    USHORT sendto_as_len = 0;
    struct cert_obj_st_t *ap_cert_obj ;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_certificate_auth_request_create\n");

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "STA " MACSTR " doesn't exist in the sta table \n", MAC2STR(pAddr));
        return 0;
    }

    ap_cert_obj =pAd->cert_info.local_cert_obj;

    /* addid */
    sendto_as_len = pack_addid((UINT8 *)&pEntry->ADDID, sendto_as, sendto_as_len);
    /* ae nonce */
    sendto_as_len = c_pack_32bytes((UINT8 *)&pEntry->ANONCE,sendto_as,sendto_as_len,MAX_WAI_AUTH_HS_LEN);
    /* asue nonce */
    sendto_as_len = c_pack_32bytes((UINT8 *)&pEntry->SNONCE,sendto_as,sendto_as_len,MAX_WAI_AUTH_HS_LEN);

    /*ASUE certificate*/
    sendto_as_len = c_pack_word(&pEntry->user_cert.cert_flag,sendto_as ,sendto_as_len,FROM_MT_LEN);
    sendto_as_len = c_pack_word(&pEntry->user_cert.cert_len,sendto_as ,sendto_as_len,FROM_MT_LEN);
    memcpy(sendto_as + sendto_as_len, pEntry->user_cert.cert_data, pEntry->user_cert.cert_len);
    sendto_as_len += pEntry->user_cert.cert_len;

    /*AE certificate*/
    printf("process_accessrequest:cert_index=%d\n",pAd->cert_info.config.used_cert);
    sendto_as_len = c_pack_word(&pAd->cert_info.config.used_cert, sendto_as ,sendto_as_len,FROM_MT_LEN);
    sendto_as_len = c_pack_word(&ap_cert_obj->cert_bin->length,sendto_as,sendto_as_len,FROM_MT_LEN);
    memcpy(sendto_as + sendto_as_len, ap_cert_obj->cert_bin->data, ap_cert_obj->cert_bin->length);
    sendto_as_len += pAd->cert_info.local_cert_obj->cert_bin->length;

#if 0
    if(pEntry->asu_id_list.identifier == 3)
    {
        printf("push asue trust lists\n");
        memcpy(sendto_as + offset, (UINT8 *)&(sta_auth_requ->asu_id_list), sta_auth_requ->asu_id_list.id_no * 4 + 6);
        offset += sta_auth_requ->asu_id_list.id_no * 4 + 6;
    }
#endif
    if(pEntry->asu_id_list.identifier == ID_LIST)
    {
        INT idx;

        sendto_as_len = c_pack_byte((UINT8 *)&(pEntry->asu_id_list.identifier), sendto_as, sendto_as_len,FROM_MT_LEN);
        sendto_as_len = c_pack_word((UINT16 *)&(pEntry->asu_id_list.length), sendto_as,sendto_as_len,FROM_MT_LEN);
        sendto_as_len = c_pack_byte((UINT8 *)&(pEntry->asu_id_list.rev), sendto_as, sendto_as_len,FROM_MT_LEN);
        sendto_as_len = c_pack_word((UINT16 *)&(pEntry->asu_id_list.id_no), sendto_as,sendto_as_len,FROM_MT_LEN);

        for(idx=0; idx<pEntry->asu_id_list.id_no; idx++)
        {
            sendto_as_len = c_pack_word((UINT16 *)&(pEntry->asu_id_list.id[idx].id_flag), sendto_as,sendto_as_len,FROM_MT_LEN);
            sendto_as_len = c_pack_word((UINT16 *)&(pEntry->asu_id_list.id[idx].id_len), sendto_as,sendto_as_len,FROM_MT_LEN);
            sendto_as_len = c_pack_nbytes((UINT8 *)&(pEntry->asu_id_list.id[idx].id_data),
                                          pEntry->asu_id_list.id[idx].id_len, sendto_as, sendto_as_len,FROM_MT_LEN);
        }
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_certificate_auth_request_create\n");
    return sendto_as_len;
}

SHORT wapi_certificate_auth_response_check(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   recvfrom_as,
    IN USHORT   recvfrom_as_len,
    OUT PUCHAR  ecdhKey)
{
    UINT8   errorcode_toASUE=0;
    UINT8   errorcode_toAE=0;
    UCHAR   hash_value[32]= {0,};
    INT     auth_error = 0;
    USHORT  no_signdata_len = 0;
    USHORT  no_signdata_len1 = 0;
    USHORT  cert_type;
    USHORT  offset = 0;
    certificate_auth_response   auth_res_buff;
    big_data            data_buff;
    tkey                *pubkey = NULL;
    wai_fixdata_id      as_id, ca_id;
    const struct cert_obj_st_t  *cert_obj = NULL;
    STA_TABLE_ENTRY  *pEntry = NULL;
    EC_KEY *ae_eck = NULL;
    EC_KEY  *asue_eck = NULL;
    USHORT  status = 0;
    int use_ca_cert=0;


    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_certificate_auth_response_check\n");

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "STA " MACSTR " doesn't exist in the sta table \n", MAC2STR(pAddr));
        status = -1;
        goto err;
    }

    memset(&auth_res_buff, 0, sizeof(certificate_auth_response));
    memset(&data_buff, 0, sizeof(big_data));

    offset = unpack_certificate_auth_response(&auth_res_buff,  recvfrom_as,  recvfrom_as_len, &no_signdata_len, &no_signdata_len1);
    if (offset == PACK_ERROR)
    {
        auth_error = -1;
        DBGPRINT(RT_DEBUG_ERROR, "wapi_certificate_auth_response_check -- unpack_certificate_auth_response :PACK_ERROR\n");
        status = -3;
        goto err;
    }

    if (memcmp(pEntry->ANONCE, auth_res_buff.cert_result.cert_result.ae_challenge, 32) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "^^^^^^^^^^^^ae_nonce not same\n");
        DBGPRINT(RT_DEBUG_ERROR, "current:");
        hex_dump("ae_nonce", auth_res_buff.cert_result.cert_result.ae_challenge, 32);
        DBGPRINT(RT_DEBUG_ERROR, "saved:");
        hex_dump("ae_nonce", pEntry->ANONCE, 32);
        status = -4;
        goto err;
    }

    memset(&as_id, 0, sizeof(wai_fixdata_id ));
    memset(&ca_id, 0, sizeof(wai_fixdata_id ));
    if(wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->asu_cert_st[0],
                               &(as_id), pAd->cert_info.config.used_cert)!=0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wai_fixdata_id_by_ident fail (asu)\n");
        status = -4;
        goto err;
    }

    if((pAd->cert_info.config.cert_mode == THREE_CERTIFICATE_MODE) &&
       (wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->ca_cert_st,
                                &(ca_id), pAd->cert_info.config.used_cert)!=0))
    {
        DBGPRINT(RT_DEBUG_ERROR, "wai_fixdata_id_by_ident fail (ca)\n");
        status = -4;
        goto err;
    }

    if((auth_res_buff.cert_result.ae_trust_asu_sign.id.id_len != as_id.id_len)||
       (memcmp(auth_res_buff.cert_result.ae_trust_asu_sign.id.id_data,
               as_id.id_data, as_id.id_len)!=0))
    {
        if((pAd->cert_info.config.cert_mode == THREE_CERTIFICATE_MODE) &&
           (auth_res_buff.cert_result.ae_trust_asu_sign.id.id_len == ca_id.id_len)&&
           (memcmp(auth_res_buff.cert_result.ae_trust_asu_sign.id.id_data,
                   ca_id.id_data, ca_id.id_len)==0))
        {
            use_ca_cert=1;
        }
        else
        {
            DBGPRINT(RT_DEBUG_ERROR, "wapi_certificate_auth_response_check -- not trust as/ca\n");
            hex_dump("ae trust asu sign id", auth_res_buff.cert_result.ae_trust_asu_sign.id.id_data,
                     auth_res_buff.cert_result.ae_trust_asu_sign.id.id_len);
            hex_dump("asu_id", as_id.id_data, as_id.id_len);
            hex_dump("ca_id", ca_id.id_data, ca_id.id_len);
            status = -4;
            goto err;
        }
    }

    mhash_sha256(auth_res_buff.cert_result.cert_result.cert1.cert_bin.data,
                 auth_res_buff.cert_result.cert_result.cert1.cert_bin.length, hash_value);
    if(memcmp(pEntry->asue_cert_hash, hash_value, 32)!=0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "receive auth response with mismatch asue cert\n");
        status = -4;
        goto err;
    }

    if(cmp_oid(auth_res_buff.cert_result.ae_trust_asu_sign.alg.sign_para.para_data,
               auth_res_buff.cert_result.ae_trust_asu_sign.alg.sign_para.para_len)!=0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "public key oid sig not same\n");
        status = -4;
        goto err;
    }

    data_buff.length = no_signdata_len1 - sizeof(wai_fixdata_addid);
    memcpy(data_buff.data, recvfrom_as + sizeof(wai_fixdata_addid), data_buff.length);

    cert_type = pAd->cert_info.config.used_cert;
    cert_obj = get_cert_obj(cert_type);
    if((cert_obj == NULL)
       ||(cert_obj->obj_new == NULL)
       ||(cert_obj->obj_free == NULL)
       ||(cert_obj->decode == NULL)
       ||(cert_obj->encode == NULL)
       ||(cert_obj->cmp == NULL)
       ||(cert_obj->get_public_key == NULL)
       ||(cert_obj->get_subject_name == NULL)
       ||(cert_obj->get_issuer_name == NULL)
       ||(cert_obj->get_serial_number == NULL)
       ||(cert_obj->verify_key == NULL)
       ||(cert_obj->sign == NULL)
       ||(cert_obj->verify == NULL))
    {
        DBGPRINT(RT_DEBUG_ERROR, "Not found cert_obj\n");
        status = -4;
        goto err;
    }

    if(use_ca_cert)
    {
        pubkey = (*cert_obj->get_public_key)(pAd->cert_info.local_cert_obj->ca_cert_st);
    }
    else
    {
        pubkey = (*cert_obj->get_public_key)(pAd->cert_info.local_cert_obj->asu_cert_st[0]);
    }

    if(!(*cert_obj->verify)(pubkey->data, pubkey->length,
                            data_buff.data,data_buff.length,
                            auth_res_buff.cert_result.ae_trust_asu_sign.sign_data.data,
                            auth_res_buff.cert_result.ae_trust_asu_sign.sign_data.length))
    {
        free_buffer(pubkey, sizeof(tkey));
        DBGPRINT(RT_DEBUG_ERROR, "%s sign error!!!\n", use_ca_cert ? "CA" : "ASUE");
        errorcode_toASUE = CERTIFSIGNERR;
        auth_error = -1;
        status = -4;
        goto err;
    }

    free_buffer(pubkey, sizeof(tkey));

    errorcode_toASUE = auth_res_buff.cert_result.cert_result.auth_result1;
    errorcode_toAE = auth_res_buff.cert_result.cert_result.auth_result2;

    pEntry->asue_auth_result = errorcode_toASUE;

    if((errorcode_toASUE == 0) && (errorcode_toAE == 0))
    {
        UCHAR  ecdhkey[24] = {0,};
        INT  ecdhkeyl = 0;

        ae_eck = geteckey_by_curve(NID_X9_62_prime192v1);

        if(ae_eck == NULL)
        {
            DBGPRINT(RT_DEBUG_ERROR, "genernate AE Curve fail\n");
            status = -1;
            goto err;
        }
        else if (!EC_KEY_generate_key(ae_eck))
        {
            DBGPRINT(RT_DEBUG_ERROR, "genernate AE ECC Key fail\n");
            status = -1;
            goto err;
        }

        pEntry->ae_key_data.length = point2bin(ae_eck, (UINT8*)(&pEntry->ae_key_data.data), MAX_BYTE_DATA_LEN);

        asue_eck = octkey2eckey(pEntry->asue_key_data.data, pEntry->asue_key_data.length, NULL, 0, NID_X9_62_prime192v1);

        ecdhkeyl  = ECDH_compute_key(ecdhkey, 24, EC_KEY_get0_public_key(asue_eck), ae_eck, NULL);
        printf("ecdhkeyl = %d\n", ecdhkeyl);
        memcpy(ecdhKey, ecdhkey, 24);

        assert(ecdhkeyl >= 0);

        hex_dump("ecdh key", ecdhKey, 24);

    }
    else
    {
        DBGPRINT(RT_DEBUG_ERROR, "errorcode_toASUE(%d), errorcode_toAE(%d)\n", errorcode_toASUE, errorcode_toAE);
        status = -1;
        goto err;
    }

err:
    if(ae_eck)
        EC_KEY_free(ae_eck);
    if(asue_eck)
        EC_KEY_free(asue_eck);

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_certificate_auth_response_check\n");
    return status;
}

USHORT wapi_access_auth_response_create(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   sendto_asue,
    IN PUCHAR   recvfrom_as,
    IN USHORT   recvfrom_as_len)
{
    USHORT  sign_len_pos = 0;
    USHORT  sign_val_len = 48;
    USHORT  sendto_asue_len = 0;
    big_data    data_buff;
    tsign   sign;
    UCHAR   flag;
    STA_TABLE_ENTRY  *pEntry = NULL;
    INT idlen = sizeof(wai_fixdata_addid);
    SHORT   status = 0;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_access_auth_response_create\n");

    // Look up the STA info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "STA " MACSTR " doesn't exist in the sta table \n", MAC2STR(pAddr));
        status = -1;
        goto err;
    }

    flag = pEntry->id_flag & 0x03;

    if (pEntry->id_flag & WAI_FLAG_CERT_REQ)
        flag |= WAI_FLAG_OPTION;

    // update identification flag
    (*sendto_asue) = flag;
    sendto_asue_len++;

    /* asue nonce */
    sendto_asue_len = c_pack_32bytes((UINT8 *)&pEntry->SNONCE,sendto_asue,sendto_asue_len,MAX_WAI_AUTH_HS_LEN);
    /* ae nonce */
    sendto_asue_len = c_pack_32bytes((UINT8 *)&pEntry->ANONCE,sendto_asue,sendto_asue_len,MAX_WAI_AUTH_HS_LEN);
    /* asue auth result */
    sendto_asue_len = c_pack_byte((UINT8 *)&pEntry->asue_auth_result,sendto_asue,sendto_asue_len,MAX_WAI_AUTH_HS_LEN);

    sendto_asue_len = c_pack_byte_data(&pEntry->asue_key_data,sendto_asue,sendto_asue_len,MAX_WAI_AUTH_HS_LEN);
    if(sendto_asue_len == PACK_ERROR)
    {
        DBGPRINT(RT_DEBUG_ERROR, "err in %s:%d\n", __func__, __LINE__);
        status = -1;
        goto err;
    }

    sendto_asue_len = c_pack_byte_data(&pEntry->ae_key_data,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    if(sendto_asue_len == PACK_ERROR)
    {
        DBGPRINT(RT_DEBUG_ERROR, "err in %s:%d\n", __func__, __LINE__);
        status = -1;
        goto err;
    }

    sendto_asue_len = c_pack_word(&pAd->local_user_id.id_flag,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    sendto_asue_len = c_pack_word(&pAd->local_user_id.id_len,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    memcpy(sendto_asue + sendto_asue_len, pAd->local_user_id.id_data, pAd->local_user_id.id_len);
    sendto_asue_len += pAd->local_user_id.id_len;

    sendto_asue_len = c_pack_word(&pEntry->user_id.id_flag,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    sendto_asue_len = c_pack_word(&pEntry->user_id.id_len,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    memcpy(sendto_asue + sendto_asue_len, pEntry->user_id.id_data, pEntry->user_id.id_len);
    sendto_asue_len +=  pEntry->user_id.id_len;

    if(flag & WAI_FLAG_OPTION)
    {
        memcpy(sendto_asue + sendto_asue_len, recvfrom_as + idlen, recvfrom_as_len - idlen);
        sendto_asue_len += (recvfrom_as_len - idlen);
    }

    data_buff.length = sendto_asue_len;
    memcpy(data_buff.data, sendto_asue, data_buff.length);
    sign.length = (*pAd->cert_info.local_cert_obj->sign)(
                      pAd->cert_info.local_cert_obj->private_key->data,
                      pAd->cert_info.local_cert_obj->private_key->length,
                      data_buff.data,     data_buff.length, sign.data);

    assert(sign.length != 0);

    if(sign.length == 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "err in %s:%d\n", __func__, __LINE__);
        status = -1;
        goto err;
    }

    *(sendto_asue + sendto_asue_len) = 1;
    sendto_asue_len += 1;
    sign_len_pos = sendto_asue_len;
    sendto_asue_len += 2;

    sendto_asue_len = c_pack_word(&pAd->local_user_id.id_flag,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    sendto_asue_len = c_pack_word(&pAd->local_user_id.id_len,sendto_asue,sendto_asue_len,FROM_AS_LEN);
    memcpy(sendto_asue + sendto_asue_len, &pAd->local_user_id.id_data, pAd->local_user_id.id_len);
    sendto_asue_len += pAd->local_user_id.id_len;

    sendto_asue_len = c_pack_sign_alg(&pAd->sign_alg, sendto_asue,sendto_asue_len,FROM_AS_LEN);
    sendto_asue_len = c_pack_word((UINT16 *)&sign_val_len,sendto_asue,sendto_asue_len,FROM_AS_LEN);

    memcpy(sendto_asue + sendto_asue_len, sign.data, 48);
    sendto_asue_len += 48;

    sendto_asue[sign_len_pos] = ((sendto_asue_len - sign_len_pos - 2)>>8)&0xff;
    sendto_asue[sign_len_pos+1] = ((sendto_asue_len - sign_len_pos - 2))&0xff;

err:

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_access_auth_response_create\n");

    if (status == -1)
        return 0;
    else
        return sendto_asue_len;
}

SHORT wapi_access_auth_response_check(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR   pAddr,
    IN PUCHAR   recvfrom_ae,
    IN USHORT   recvfrom_ae_len,
    OUT PUCHAR  ecdhKey)
{
    STA_TABLE_ENTRY  *pEntry = NULL;
    wapi_access_auth_response   access_auth_res_buff;
    big_data    data_buff;
    USHORT  offset = 0;
    USHORT  no_signdata_len = 0;
    UCHAR  ecdhkey[24] = {0,};
    INT  ecdhkeyl = 0;
    EC_KEY *ae_eck = NULL;
    EC_KEY  *asue_eck = NULL;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_access_auth_response_check\n");
    // Look up the mac table info
    pEntry = StaTableLookup(pAd, pAddr);

    if (pEntry == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "STA " MACSTR " doesn't exist in the sta table \n", MAC2STR(pAddr));
        return -1;
    }

    memset(&access_auth_res_buff, 0, sizeof(access_auth_res_buff));
    memset(&data_buff, 0, sizeof(big_data));

    offset = unpack_access_auth_response(&access_auth_res_buff,  recvfrom_ae,  recvfrom_ae_len, &no_signdata_len);
    if(offset == PACK_ERROR)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_response_check -- unpack_access_auth_response :PACK_ERROR\n");
        return -3;
    }

    asue_eck = octkey2eckey(pEntry->asue_key_data.data, pEntry->asue_key_data.length, pEntry->private_key.data, pEntry->private_key.length, NID_X9_62_prime192v1);
    ae_eck = octkey2eckey(access_auth_res_buff.ae_key_data.data, access_auth_res_buff.ae_key_data.length, NULL, 0, NID_X9_62_prime192v1);

    ecdhkeyl  = ECDH_compute_key(ecdhkey, 24, EC_KEY_get0_public_key(ae_eck), asue_eck, NULL);
    memcpy(ecdhKey, ecdhkey, 24);

    assert(ecdhkeyl >= 0);

    hex_dump("ecdh key", ecdhKey, 24);

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_access_auth_response_check\n");
    return 0;
}

