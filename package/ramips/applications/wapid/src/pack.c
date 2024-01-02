
#include <memory.h>
#include <stdio.h>
#include <netinet/in.h>

#include "pack.h"
#include "debug.h"
#include "common.h"
#include "wapi.h"

#define RAND_LEN    32

inline static
void write_byte(void* buffer,UCHAR content,USHORT site)
{
    *(((UCHAR*)buffer)+site) = content;
}

inline static
void write_word(void* buffer,USHORT content,USHORT site)
{
    content = htons(content);
    memcpy ((UCHAR*)buffer+site, &content, 2);
}

inline static
void write_dword(void* buffer,ULONG content,USHORT site)
{
    content = htonl(content);
    memcpy( (UCHAR*)buffer+site, &content, 4);
}

inline static
UCHAR read_byte(const void* buffer,USHORT site)
{
    UCHAR result = *(((UCHAR*)buffer)+site);
    return result;
}

inline static
USHORT read_word(const void* buffer,USHORT site)
{
    USHORT result;
    UCHAR *pos = (UCHAR *)buffer + site;

    result = ((pos[0]<<8)|pos[1])&0xffff;
    return result;
}

inline static
ULONG read_dword(const void* buffer,USHORT site)
{
    ULONG result;
    memcpy(&result, (UCHAR*)buffer+site, 4);
    result = ntohl(result);

    return result;
}

SHORT c_pack_nbytes(const UCHAR* content, INT n, void* buffer,USHORT offset,USHORT bufflen)
{
    const UCHAR *temp = content ;
    if( offset+n>bufflen ) return PACK_ERROR;
    memcpy(buffer+offset, temp, n);
    return offset+n;
}
SHORT  c_pack_byte(const UCHAR* content,void* buffer,USHORT offset,USHORT bufflen)
{
    if( offset+1>bufflen ) return PACK_ERROR;
    write_byte(buffer,*content,offset);
    offset ++;
    return offset;
}

SHORT  c_pack_word(const USHORT* content,void* buffer,USHORT offset,USHORT bufflen)
{
    if( offset+2>bufflen ) return PACK_ERROR;
    write_word(buffer,*content,offset);
    offset += 2;
    return offset;
}

SHORT  c_pack_dword(const ULONG* content,void* buffer,USHORT offset,USHORT bufflen)
{
    if( offset+4>bufflen ) return PACK_ERROR;
    write_dword(buffer,*content,offset);
    offset +=4;
    return offset;
}

SHORT  c_pack_32bytes(const UCHAR* content,void* buffer,USHORT offset,USHORT bufflen)
{
    return  c_pack_nbytes(content, 32, buffer,offset, bufflen);
}

SHORT  c_pack_byte_data(const byte_data* pData,void* buffer,USHORT offset,USHORT bufflen)
{
    if(     offset+pData->length+1 > bufflen)
        return PACK_ERROR;

    offset = c_pack_byte(&pData->length,buffer,offset,bufflen);
    memcpy((UINT8*)buffer+offset,pData->data,pData->length);
    offset += pData->length;

    return offset;
}

SHORT  c_pack_sign_alg(const wai_fixdata_alg *pSign_alg,void* buffer,USHORT offset,USHORT bufflen)
{
    if( offset+pSign_alg->alg_length + 2>bufflen ) return PACK_ERROR;

    offset = c_pack_word(&pSign_alg->alg_length,buffer,offset,bufflen);
    offset = c_pack_byte(&pSign_alg->sha256_flag,buffer,offset,bufflen);
    offset = c_pack_byte(&pSign_alg->sign_alg,buffer,offset,bufflen);
    offset = c_pack_byte(&pSign_alg->sign_para.para_flag,buffer,offset,bufflen);
    offset = c_pack_word(&pSign_alg->sign_para.para_len,buffer,offset,bufflen);
    memcpy(buffer + offset, pSign_alg->sign_para.para_data, pSign_alg->sign_para.para_len);
    offset += pSign_alg->sign_para.para_len;
    return offset;
}

SHORT  c_pack_packet_head( packet_head *pHead,void* buffer,USHORT offset,USHORT bufflen)
{
    if( bufflen<sizeof(packet_head) )
        return PACK_ERROR;

    offset = c_pack_word(&(pHead->version),buffer,offset,bufflen);
    offset = c_pack_byte(&(pHead->type),buffer,offset,bufflen);
    offset = c_pack_byte(&(pHead->sub_type),buffer,offset,bufflen);
    offset = c_pack_word(&(pHead->reserved),buffer,offset,bufflen);
    offset = c_pack_word(&(pHead->data_len),buffer,offset,bufflen);
    offset = c_pack_word(&(pHead->group_sc),buffer,offset,bufflen);
    offset = c_pack_byte(&(pHead->frame_sc),buffer,offset,bufflen);
    offset = c_pack_byte(&(pHead->flag),buffer,offset,bufflen);

    return offset;
}
SHORT pack_mac(const UCHAR* pData, void* buffer, SHORT offset)
{
    memcpy((UINT8*)buffer+offset, pData, 6);
    offset += 6;

    return offset;
}

SHORT pack_addid(const UCHAR* pData, void* buffer, SHORT offset)
{
    memcpy((UINT8*)buffer+offset, pData, 12);
    offset += 12;

    return offset;
}

SHORT  c_unpack_byte(UINT8* content, const void* buffer,USHORT offset,USHORT bufflen)
{
    if(offset+1>bufflen) return PACK_ERROR;
    *content = read_byte(buffer,offset);
    offset ++;

    return offset;
}
SHORT  c_unpack_word(USHORT* content, const void* buffer,USHORT offset,USHORT bufflen)
{
    if( offset+2>bufflen ) return PACK_ERROR;
    *content = read_word(buffer,offset);
    offset += 2;

    return offset;
}
SHORT  c_unpack_dword(ULONG* content, const void* buffer,USHORT offset,USHORT bufflen)
{
    if( offset+4>bufflen ) return PACK_ERROR;
    *content = read_dword(buffer,offset);
    offset += 4;

    return offset;
}

SHORT  c_unpack_32bytes(UCHAR* content, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    int i;
    if(offset+32>bufflen) return PACK_ERROR;
    for(i = 0; i < 32; i ++)
    {
        *(content + i) = read_byte(buffer,offset);
        offset ++;
    }
    return offset;
}
SHORT  c_unpack_period(pov *p_pov,const void* buffer,UINT16 offset,UINT16 bufflen)
{
    if( offset+sizeof(pov)>bufflen ) return PACK_ERROR;
    offset = c_unpack_dword(&p_pov->not_before,buffer,offset,bufflen);
    offset = c_unpack_dword(&p_pov->not_after, buffer,offset,bufflen);

    return offset;
}
SHORT  c_unpack_sign_alg(wai_fixdata_alg* p_sign_alg,const void* buffer,UINT16 offset,UINT16 bufflen)
{

    memset((UINT8 *)p_sign_alg, 0, sizeof(wai_fixdata_alg));

    if( offset+2>bufflen ) return PACK_ERROR;
    p_sign_alg->alg_length = read_word(buffer,offset);
    offset += 2;

    if( offset+1>bufflen ) return PACK_ERROR;
    p_sign_alg->sha256_flag = read_byte(buffer,offset);
    offset += 1;

    if( offset+1>bufflen ) return PACK_ERROR;
    p_sign_alg->sign_alg = read_byte(buffer,offset);
    offset += 1;

    if( offset+1>bufflen ) return PACK_ERROR;
    p_sign_alg->sign_para.para_flag = read_byte(buffer,offset);
    offset += 1;

    if( offset+2>bufflen ) return PACK_ERROR;
    p_sign_alg->sign_para.para_len = read_word(buffer,offset);
    offset += 2;

    if( offset+p_sign_alg->sign_para.para_len >bufflen )
    {
        return PACK_ERROR;
    }
    memcpy(p_sign_alg->sign_para.para_data, buffer + offset , p_sign_alg->sign_para.para_len);
    offset += p_sign_alg->sign_para.para_len;

    return offset;
}

SHORT  c_unpack_pubkey(pubkey_data* p_pubkey,const void* buffer,UINT16 offset,UINT16 bufflen)
{
    memset((UINT8 *)p_pubkey, 0, sizeof(pubkey_data));

    offset = c_unpack_word(&p_pubkey->length, buffer,offset,bufflen);

    if( offset+p_pubkey->length >bufflen ) return PACK_ERROR;

    offset = c_unpack_byte(&p_pubkey->pubkey_alg_flag, buffer,offset,bufflen);
    offset = c_unpack_byte(&p_pubkey->pubkey_para.para_flag, buffer,offset,bufflen);
    offset = c_unpack_word(&p_pubkey->pubkey_para.para_len, buffer,offset,bufflen);

    if(p_pubkey->pubkey_para.para_len  > MAX_PARA_LEN)   return PACK_ERROR;
    memcpy(p_pubkey->pubkey_para.para_data, buffer + offset, p_pubkey->pubkey_para.para_len);
    offset += p_pubkey->pubkey_para.para_len;

    if((p_pubkey->length
        -1
        -1
        -2
        -p_pubkey->pubkey_para.para_len )
       > COMM_DATA_LEN)   return PACK_ERROR;
    memcpy(p_pubkey->pubkey_data, buffer + offset , p_pubkey->length-1-1-2-p_pubkey->pubkey_para.para_len );
    offset +=p_pubkey->length   -1-1-2-p_pubkey->pubkey_para.para_len ;

    return offset;
}

SHORT  c_unpack_byte_data(byte_data *p_byte_data, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    if(offset +1 >bufflen)  return PACK_ERROR;
    p_byte_data->length = read_byte(buffer, offset);
    offset += 1;

    if( (offset+p_byte_data->length > bufflen) ||(p_byte_data->length == 0)) /*if array beyond thye mark*/
        return PACK_ERROR;
    memcpy(p_byte_data->data, (UINT8*)buffer+offset, p_byte_data->length);
    offset += p_byte_data->length;

    return offset;
}
SHORT  c_unpack_comm_data(comm_data *p_byte_data, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    if(offset +2 >bufflen)  return PACK_ERROR;
    p_byte_data->length = read_word(buffer, offset);
    offset += 2;

    if( (offset+p_byte_data->length > bufflen) ||
        (p_byte_data->length > COMM_DATA_LEN)||
        (p_byte_data->length == 0)) /*if array beyond thye mark*/
        return PACK_ERROR;

    memcpy(p_byte_data->data, (UINT8*)buffer+offset, p_byte_data->length);
    offset += p_byte_data->length;
    return offset;
}
SHORT  c_unpack_id_data(cert_id_data *p_byte_data, const void* buffer, UINT16 offset,UINT16 bufflen)
{
    offset = c_unpack_word(&p_byte_data->length, buffer, offset, bufflen);

    if( (offset+p_byte_data->length > bufflen) ||
        (p_byte_data->length > MAX_ID_DATA_LEN)||
        (p_byte_data->length == 0))
    {
        return PACK_ERROR;
    }
    memcpy(p_byte_data->id_data, (UINT8*)buffer+offset, p_byte_data->length - 2);
    offset += p_byte_data->length - 2;

    return offset;
}
SHORT  unpack_head(packet_head *p_head,const void* buffer,UINT16 bufflen)
{
    UINT16 offset = 0;
    offset = c_unpack_word(&p_head->version, buffer,offset,bufflen);
    offset = c_unpack_byte(&p_head->type, buffer,offset,bufflen);
    offset = c_unpack_byte(&p_head->sub_type, buffer,offset,bufflen);
    offset = c_unpack_word(&p_head->reserved, buffer,offset,bufflen);
    offset = c_unpack_word(&p_head->data_len, buffer,offset,bufflen);
    offset = c_unpack_word(&p_head->group_sc, buffer,offset,bufflen);
    offset = c_unpack_byte(&p_head->frame_sc, buffer,offset,bufflen);
    offset = c_unpack_byte(&p_head->flag, buffer,offset,bufflen);
    return offset;
}

VOID  set_packet_data_len(void* buffer,const UINT16 the_len)
{
    static UINT16 site = 6;
    write_word(buffer,the_len,site);
}

UINT16  get_packet_data_len(const void* buffer)
{
    static UINT16 site = 6;
    return read_word(buffer,site);
}

SHORT unpack_wai_fixdata_cert(wai_fixdata_cert*pcert, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    UINT16 temp_len = 0;

    if(offset + 2 > bufflen) return PACK_ERROR;
    offset = c_unpack_word(&pcert->cert_flag, buffer,  offset, bufflen);

    if(offset + 2 > bufflen) return PACK_ERROR;
    offset = c_unpack_word(&pcert->cert_bin.length, buffer,  offset, bufflen);

    temp_len = pcert->cert_bin.length;
    if(offset + temp_len > bufflen)
        return PACK_ERROR;

    //pcert->cert_len = pcert->cert_bin.length;
    //memcpy(&pcert->cert_data, (UINT8 *)buffer + offset, pcert->cert_len);

    pcert->cert_bin.data = (unsigned char *)buffer + offset;
    offset += temp_len;

    return offset;
}

SHORT unpack_wai_fixdata_id(wai_fixdata_id*pid, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    if(offset + 2 > bufflen) return PACK_ERROR;
    offset = c_unpack_word(&pid->id_flag, buffer, offset,  bufflen);
    if(offset + 2 > bufflen) return PACK_ERROR;
    offset = c_unpack_word(&pid->id_len, buffer, offset,  bufflen);
    if(offset + pid->id_len > bufflen) return PACK_ERROR;
    memcpy(&pid->id_data, buffer + offset, pid->id_len);
    offset += pid->id_len;
    return offset;
}

SHORT unpack_wai_attridata_cert_check_result(wai_attridata_auth_result*pid_list, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    if(offset + 1 > bufflen) return PACK_ERROR;
    offset = c_unpack_byte(&pid_list->identifier, buffer,  offset, bufflen);

    if(offset + 2 > bufflen) return PACK_ERROR;
    offset = c_unpack_word(&pid_list->length, buffer,  offset, bufflen);
    if(offset + pid_list->length > bufflen)
    {
        return PACK_ERROR;
    }

    offset = c_unpack_32bytes((UINT8 *)&pid_list->ae_challenge, buffer,  offset, bufflen);
    offset = c_unpack_32bytes((UINT8 *)&pid_list->asue_challenge, buffer,  offset, bufflen);

    if(offset + 1 > bufflen) return PACK_ERROR;
    offset = c_unpack_byte(&pid_list->auth_result1, buffer,  offset, bufflen);

    offset = unpack_wai_fixdata_cert(&pid_list->cert1, buffer,offset, bufflen);
    if(offset == PACK_ERROR ) return PACK_ERROR;

    if(offset + 1 > bufflen) return PACK_ERROR;
    offset = c_unpack_byte(&pid_list->auth_result2, buffer,  offset, bufflen);

    offset = unpack_wai_fixdata_cert(&pid_list->cert2, buffer,offset, bufflen);
    if(pid_list->length != 32 /*ae_challenge*/
       + 32 /*asue_challenge*/
       + 1 /*auth_result1*/
       + 4 /*cer flag | cert len*/
       + pid_list->cert1.cert_bin.length
       + 1 /*auth_result2*/
       + 4  /*cer flag | cert len*/
       + pid_list->cert2.cert_bin.length)
    {

        return PACK_ERROR;
    }
    return offset;
}
SHORT unpack_wai_attridata_id_list(wai_attridata_id_list*pid_list, const void* buffer,UINT16 offset,UINT16 bufflen)
{
    UINT16  i;

    offset = c_unpack_byte(&pid_list->identifier, buffer,  offset, bufflen);
    offset = c_unpack_word(&pid_list->length, buffer,  offset, bufflen);
    offset = c_unpack_byte(&pid_list->rev, buffer,  offset, bufflen);
    offset = c_unpack_word(&pid_list->id_no, buffer,  offset, bufflen);

    for(i =0; i< pid_list->id_no; i++)
        offset = unpack_wai_fixdata_id(&pid_list->id[i], buffer, offset, bufflen);
    return offset;
}

SHORT unpack_wai_attridata_auth_payload(wai_attridata_auth_payload  *pasue_sign,
                                        const void* buffer,UINT16 offset,UINT16 bufflen)
{
    if(offset + 1 > bufflen) return PACK_ERROR;
    offset = c_unpack_byte(&pasue_sign->identifier, buffer,  offset, bufflen);
    if(pasue_sign->identifier !=1) return PACK_ERROR;

    if(offset + 2 > bufflen) return PACK_ERROR;
    offset = c_unpack_word(&pasue_sign->length, buffer,  offset, bufflen);

    offset = unpack_wai_fixdata_id(&pasue_sign->id, buffer, offset, bufflen);
    if( offset==PACK_ERROR ) return PACK_ERROR;

    offset = c_unpack_sign_alg(&pasue_sign->alg, buffer, offset, bufflen);
    if( offset==PACK_ERROR ) return PACK_ERROR;

    offset = c_unpack_comm_data(&pasue_sign->sign_data, buffer,  offset, bufflen);
    if( offset==PACK_ERROR ) return PACK_ERROR;

    if(pasue_sign->length != 4 /*id flag | id len*/
       + pasue_sign->id.id_len
       + 2  /*alg_length len*/
       + pasue_sign->alg.alg_length
       + 2 /*sign data len*/
       + pasue_sign->sign_data.length)
    {

        return PACK_ERROR;
    }
    return offset;

}

SHORT  unpack_access_auth_request(
    access_auth_request *p_sta_auth_request,
    const void* buffer,
    UINT16 bufflen,
    UINT16 *no_signdata_len)
{
    UINT16 offset = 0 ;

    offset = c_unpack_byte((UINT8 *)&p_sta_auth_request->flag,buffer,offset,bufflen);
    offset = c_unpack_32bytes((UINT8 *)&p_sta_auth_request->ae_auth_flag,buffer,offset,bufflen);
    offset = c_unpack_32bytes((UINT8 *)&p_sta_auth_request->asue_challenge,buffer,offset,bufflen);
    offset = c_unpack_byte_data(&p_sta_auth_request->key_data,buffer,offset,bufflen);

    offset =  unpack_wai_fixdata_id(&p_sta_auth_request->ae_id,  buffer, offset,  bufflen);
    if( offset==PACK_ERROR )    return PACK_ERROR;

    offset = unpack_wai_fixdata_cert(&p_sta_auth_request->asue_cert,  buffer, offset, bufflen);
    if( offset==PACK_ERROR )    return PACK_ERROR;

    offset = c_unpack_byte(&p_sta_auth_request->ecdh.para_flag,buffer,offset,bufflen);
    if( offset==PACK_ERROR )    return PACK_ERROR;

    offset = c_unpack_word(&p_sta_auth_request->ecdh.para_len,buffer,offset,bufflen);
    if( offset==PACK_ERROR )    return PACK_ERROR;

    memcpy(p_sta_auth_request->ecdh.para_data, buffer + offset, p_sta_auth_request->ecdh.para_len);
    offset += p_sta_auth_request->ecdh.para_len;
    if(*((UINT8 *)buffer + offset) == 3 && p_sta_auth_request->flag & WAI_FLAG_OPTION)
    {
        offset = unpack_wai_attridata_id_list(&p_sta_auth_request->asu_id_list,  buffer, offset, bufflen);
    }
    *no_signdata_len = offset;

    offset = unpack_wai_attridata_auth_payload(&p_sta_auth_request->asue_sign, buffer, offset, bufflen);
    if( offset==PACK_ERROR )
    {
        return PACK_ERROR;
    }

    return offset;
}

SHORT  unpack_certificate_auth_response(
    certificate_auth_response *p_auth_response,
    const void* buffer,
    UINT16 bufflen,
    UINT16 *no_signdata_len,
    UINT16 *no_signdata_len1)
{
    UINT16 offset = 0, signdata_len = 0;

    if(bufflen - offset  < 6)
        return PACK_ERROR;

    memcpy(p_auth_response->addid.mac1, buffer + offset, 6);
    offset += 6;

    if(bufflen - offset  < 6)
        return PACK_ERROR;

    memcpy(p_auth_response->addid.mac2, buffer + offset, 6);
    offset += 6;

    offset = unpack_wai_attridata_cert_check_result(&p_auth_response->cert_result.cert_result, buffer, offset, bufflen);
    if(offset == PACK_ERROR)
        return PACK_ERROR;

    if(bufflen - offset  < 2)
        return PACK_ERROR;

    memcpy(&signdata_len, buffer + offset + 1, 2);/*get sign data*/
    signdata_len = ntohs(signdata_len);

    if(p_auth_response->cert_result.cert_result.auth_result1 == CERTIFISSUERUNKNOWN )
    {
        if(bufflen - offset - 1 - 2 - signdata_len !=0 )
        {
            return PACK_ERROR;
        }
    }

    if(bufflen - offset - 1 - 2 - signdata_len > 0 )
    {
        *no_signdata_len = offset;
        offset = unpack_wai_attridata_auth_payload(&p_auth_response->cert_result.asue_trust_asu_sign, buffer, offset, bufflen);
        memcpy(&signdata_len, buffer + offset + 1, 2);/*get sign data*/
        signdata_len = ntohs(signdata_len);
        *no_signdata_len1 = offset;
        offset = unpack_wai_attridata_auth_payload(&p_auth_response->cert_result.ae_trust_asu_sign, buffer, offset, bufflen);
    }
    else if(bufflen - offset - 1 - 2 - signdata_len == 0)
    {
        *no_signdata_len1 = offset;
        offset = unpack_wai_attridata_auth_payload(&p_auth_response->cert_result.ae_trust_asu_sign, buffer, offset, bufflen);
    }
    else
    {
        return PACK_ERROR;
    }
    return offset;
}

SHORT  unpack_access_auth_response(
    wapi_access_auth_response *p_auth_response,
    const void* buffer,
    UINT16 bufflen,
    UINT16 *no_signdata_len)
{
    UINT16  offset = 0;

    offset = c_unpack_byte((UINT8 *)&p_auth_response->flag,buffer,offset,bufflen);
    offset = c_unpack_32bytes((UINT8 *)&p_auth_response->asue_challenge,buffer,offset,bufflen);
    offset = c_unpack_32bytes((UINT8 *)&p_auth_response->ae_challenge,buffer,offset,bufflen);
    offset = c_unpack_byte((UINT8 *)&p_auth_response->access_result,buffer,offset,bufflen);

    offset = c_unpack_byte_data(&p_auth_response->asue_key_data,buffer,offset,bufflen);
    if( offset==PACK_ERROR )
        return PACK_ERROR;
    offset = c_unpack_byte_data(&p_auth_response->ae_key_data,buffer,offset,bufflen);
    if( offset==PACK_ERROR )
        return PACK_ERROR;

    offset =  unpack_wai_fixdata_id(&p_auth_response->sta_aeId, buffer, offset, bufflen);
    if( offset==PACK_ERROR )
        return PACK_ERROR;

    offset =  unpack_wai_fixdata_id(&p_auth_response->sta_asueId, buffer, offset, bufflen);
    if( offset==PACK_ERROR )
        return PACK_ERROR;

    if (((p_auth_response->flag & 8) >> 3) == 1)
    {
        /*
           3 Certificates:
               CerValidResult
               AsueAsSign
               AeAsSign
               AeSign

           2 Certificates:
               CerValidResult
               AeAsSign
               AeSign
        */
        offset = unpack_wai_attridata_cert_check_result(&p_auth_response->cer_valid_result.cert_result, buffer, offset, bufflen);
        if(offset == PACK_ERROR)
            return PACK_ERROR;

        *no_signdata_len = offset;

        offset = unpack_wai_attridata_auth_payload(&p_auth_response->cer_valid_result.asue_trust_asu_sign, buffer, offset, bufflen);
        if(offset == PACK_ERROR)
            return PACK_ERROR;

        offset = unpack_wai_attridata_auth_payload(&p_auth_response->cer_valid_result.ae_trust_asu_sign, buffer, offset, bufflen);
        if(offset == PACK_ERROR)
            return PACK_ERROR;

        if (offset == bufflen)   // two Signs
        {
            memcpy(&p_auth_response->ae_sign, &p_auth_response->cer_valid_result.ae_trust_asu_sign, sizeof(p_auth_response->cer_valid_result.ae_trust_asu_sign));
            memcpy(&p_auth_response->cer_valid_result.ae_trust_asu_sign, &p_auth_response->cer_valid_result.asue_trust_asu_sign, sizeof(p_auth_response->cer_valid_result.asue_trust_asu_sign));
            memset(&p_auth_response->cer_valid_result.asue_trust_asu_sign, 0, sizeof(p_auth_response->cer_valid_result.asue_trust_asu_sign));
        }
        else // more than 2
        {
            offset = unpack_wai_attridata_auth_payload(&p_auth_response->ae_sign, buffer, offset, bufflen);
            if (offset == PACK_ERROR)
                return PACK_ERROR;
        }
    }
    else
    {
        *no_signdata_len = offset;

        offset = unpack_wai_attridata_auth_payload(&p_auth_response->ae_sign, buffer, offset, bufflen);
        if( offset==PACK_ERROR )
        {
            return PACK_ERROR;
        }
    }

    return offset;
}



SHORT unpack_ae_auth_active(auth_active *p_ae_auth_activet,const void* buffer,USHORT bufflen)
{
    USHORT  offset = 0 ;

    DBGPRINT(RT_DEBUG_TRACE, "======> unpack_ae_auth_active\n");

    offset = c_unpack_byte((UINT8 *)&p_ae_auth_activet->flag,buffer,offset,bufflen);
    offset = c_unpack_32bytes((UINT8 *)&p_ae_auth_activet->ae_auth_flag,buffer,offset,bufflen);
    offset =  unpack_wai_fixdata_id(&p_ae_auth_activet->asu_id, buffer, offset,  bufflen);
    if( offset==PACK_ERROR )
    {
        printf("unpack_ae_auth_active -- unpack_wai_fixdata_id fail !!\n");
        return PACK_ERROR;
    }

    offset = unpack_wai_fixdata_cert(&p_ae_auth_activet->ae_cer,  buffer, offset, bufflen);
    if( offset==PACK_ERROR )
    {
        printf("unpack_ae_auth_active -- unpack_wai_fixdata_cert fail !!\n");
        return PACK_ERROR;
    }

    offset = c_unpack_byte(&p_ae_auth_activet->ecdh.para_flag,buffer,offset,bufflen);
    if( offset==PACK_ERROR )
    {
        printf("unpack_ae_auth_active -- c_unpack_byte fail !!\n");
        return PACK_ERROR;
    }

    offset = c_unpack_word(&p_ae_auth_activet->ecdh.para_len,buffer,offset,bufflen);
    if( offset==PACK_ERROR )
    {
        printf("unpack_ae_auth_active -- c_unpack_word fail !!\n");
        return PACK_ERROR;
    }

    memcpy(p_ae_auth_activet->ecdh.para_data, buffer + offset, p_ae_auth_activet->ecdh.para_len);
    offset += p_ae_auth_activet->ecdh.para_len;

    DBGPRINT(RT_DEBUG_TRACE, "<====== unpack_ae_auth_active\n");

    return offset;
}

