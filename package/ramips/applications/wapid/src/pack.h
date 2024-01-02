
#ifndef _PACK_H
#define _PACK_H

#include "structure.h"
#include "type_def.h"

SHORT  c_pack_byte(const UCHAR* content,void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_pack_word(const USHORT* content,void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_pack_dword(const ULONG* content,void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_pack_32bytes(const UCHAR* content,void* buffer,USHORT offset,USHORT bufflen);
SHORT  pack_mac(const UCHAR* pData,void* buffer,SHORT offset);
SHORT  pack_addid(const UCHAR* pData,void* buffer,SHORT offset);
SHORT  c_pack_sign_alg(const wai_fixdata_alg *pSign_alg,void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_unpack_sign_alg(wai_fixdata_alg* p_sign_alg,const void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_unpack_pubkey(pubkey_data* p_pubkey,const void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_pack_byte_data(const byte_data* pData,void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_pack_packet_head(packet_head *pHead,void* buffer,USHORT offset,USHORT bufflen);
SHORT  c_pack_packed_head(void *buffer, USHORT bufflen);
SHORT  c_unpack_word(USHORT* content, const void* buffer,USHORT offset,USHORT bufflen);
SHORT  unpack_head(packet_head* p_head,const void* buffer,USHORT bufflen);
VOID   set_packet_data_len(void* buffer,const UINT16 the_len);
UINT16 get_packet_data_len(const void* buffer);
SHORT  unpack_access_auth_request(
		access_auth_request *p_sta_auth_request,
		const void* buffer,
		USHORT bufflen,
		USHORT *no_signdata_len);
SHORT  unpack_certificate_auth_response(
		certificate_auth_response *p_auth_response,
		const void* buffer,
		USHORT bufflen,
		USHORT *no_signdata_len,
		USHORT *no_signdata_len1);
SHORT  unpack_access_auth_response(
		wapi_access_auth_response *p_auth_response,
		const void* buffer,
		UINT16 bufflen,
		UINT16 *no_signdata_len);
SHORT  unpack_ae_auth_active(auth_active *p_ae_auth_activet,const void* buffer,USHORT bufflen);
#endif
