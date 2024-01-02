
#ifndef __STRUCTURE_H__
#define __STRUCTURE_H__
#include "type_def.h"

#define  WAI				0x01
#define  VERSIONNOW			0x0001
#define  RESERVEDDEF		0x0000

//#define TRUE				1
//#define FALSE				0

#define MAX_EXTENSION_TLV_ATTR   2
#define MAX_BYTE_DATA_LEN		256
#define COMM_DATA_LEN          	3000//1024
//#define MAX_DATA_LEN          1000
#define SIGN_LEN               	48
#define PUBKEY_LEN             	48
#define SECKEY_LEN             	24
#define DIGEST_LEN             	32
#define HMAC_LEN				20
#define PRF_OUTKEY_LEN			48
#define KD_HMAC_OUTKEY_LEN		96
#define	WAPI_NONCE_LEN			32

#define  AUTHACTIVE					0x03
#define  STAAUTHREQUEST				0x04
#define  STAAUTHRESPONSE			0x05
#define  APAUTHREQUEST				0x06
#define  APAUTHRESPONSE				0x07
#define  SESSIONKEYNEGREQUEST		0x08
#define  SESSIONKEYNEGRESPONSE		0x09
#define  SESSIONKEYNEGCONFIRM		0x0A
#define  GROUPKEYNOTICE				0x0B
#define  GROUPKEYNOTICERESPONSE		0x0C
#define  SENDBKTOSTA				0x10

#define CERTIFVALID					0x00
#define CERTIFISSUERUNKNOWN			0x01
#define CERTIFUNKNOWNCA				0x02
#define CERTIFEXPIRED				0x03
#define CERTIFSIGNERR				0x04
#define CERTIFREVOKED				0x05
#define CERTIFBADUSE				0x06
#define CERTUNKNOWNREVOKESTATUS		0x07
#define CERTUNKNOWNERROR			0x08

//#define USE_ATTRIBUTE_PACKED
#ifdef USE_ATTRIBUTE_PACKED
    #define __ATTRIBUTE_PACK__   __attribute__((packed))
#else
    #define __ATTRIBUTE_PACK__
#endif

#define  PACK_ERROR			0xffff

#define MAX_AKM_NO			2
#define MAX_UNICAST_NO		2
#define MAX_MULTICAST_NO	2
#define MAX_BKID_NO			2


struct _byte_data {
	UINT8  length;
	UINT8  pad_value[3];
	UINT8  data[MAX_BYTE_DATA_LEN];
} __ATTRIBUTE_PACK__;
typedef struct _byte_data   byte_data;

struct _comm_data{
 	UINT16	length;
	UINT16	pad_value;
	UINT8	data[MAX_BYTE_DATA_LEN];
}__ATTRIBUTE_PACK__;
typedef struct _comm_data comm_data,*pcomm_data; 

typedef comm_data tkey, *ptkey;
typedef comm_data tsign;

struct _big_data{
 	UINT16  length; 
	UINT16  pad_value;
	UINT8	data[COMM_DATA_LEN];
}__ATTRIBUTE_PACK__;
typedef struct _big_data big_data,*pbig_data;

#define MAX_PARA_LEN 20 
struct _para_alg {
	UINT8		para_flag;
	UINT8		pad[3];
	UINT16		para_len;
	UINT16		pad16;
	UINT8		para_data[MAX_PARA_LEN];
} __ATTRIBUTE_PACK__;
typedef struct _para_alg para_alg, *ppara_alg;

#if 0 // remove to wapi.h
#define WAI_FLAG_BK_UPDATE		0X01
#define WAI_FLAG_PRE_AUTH		0X02
#define WAI_FLAG_AUTH_CERT		0X04
#define WAI_FLAG_OPTION_BYTE	0X08
#define WAI_FLAG_USK_UPDATE		0X10
#define WAI_FLAG_STAKEY_SESSION	0X20
#define WAI_FLAG_STAKEY_DEL		0X40
#define WAI_FLAG_REV			0X80
#endif
#define MAX_CERT_DATA_LEN		1000
#define MAX_ID_DATA_LEN			1000

typedef  UINT8 wai_fixdata_flag;

struct cert_bin_t {
	unsigned short length;
	unsigned char *data;
};

typedef struct _wai_fixdata_cert {
	UINT16	cert_flag;
	struct cert_bin_t	cert_bin;
}wai_fixdata_cert;

typedef struct _wai_temp_fixdata_cert {
	UINT16	cert_flag;
	UINT16	cert_len;
	UINT8	cert_data[MAX_CERT_DATA_LEN];
}wai_temp_fixdata_cert;

struct _cert_id_data {
	UINT16	length;
	UINT8	pad_value[2];
	UINT8	id_data[MAX_ID_DATA_LEN];
} __ATTRIBUTE_PACK__;
typedef struct _cert_id_data   cert_id_data;

typedef struct _id_data {
		cert_id_data  	cert_subject;
		cert_id_data  	cert_issuer;
		cert_id_data	serial_no;
}id_data;

typedef struct _wai_fixdata_id {
	UINT16	id_flag;
	UINT16	id_len;
	UINT8 	id_data[MAX_ID_DATA_LEN];
}wai_fixdata_id;


typedef struct _wai_fixdata_addid {
	UINT8	mac1[6];
	UINT8	mac2[6];
}wai_fixdata_addid;

typedef struct _wai_fixdata_alg {
	UINT16		alg_length;
	UINT8		sha256_flag;
	UINT8		sign_alg;
	para_alg	sign_para;
}wai_fixdata_alg;

typedef struct _wai_attridata_auth_payload {
	UINT8				identifier;
	UINT8				pad8[3];
	UINT16 				length;
	UINT16				pad16[2];
	wai_fixdata_id		id;
	wai_fixdata_alg		alg;
	comm_data			sign_data;
}wai_attridata_auth_payload;

typedef struct _wai_attridata_auth_result{
	UINT8				identifier;
	UINT8 				pad;
	UINT16 				length;
	UINT8				ae_challenge[32];
	UINT8  				asue_challenge[32];
	UINT8				auth_result1;
	wai_fixdata_cert 	cert1;
	UINT8				auth_result2;
	UINT8 				pad8;
	wai_fixdata_cert	cert2;
}wai_attridata_auth_result;

#define MAX_ID_NO 10
typedef struct _wai_attridata_id_list{
	UINT8			identifier;
	UINT16			length;
	UINT8			rev;		
	UINT16			id_no;
	wai_fixdata_id	id[MAX_ID_NO];
}wai_attridata_id_list;

 struct _pov {
	ULONG not_before;
	ULONG not_after;
} __ATTRIBUTE_PACK__;
typedef struct _pov pov, *ppov; 

struct _pubkey_data{
 	UINT16		length;
	UINT16		pad16;
	UINT8		pubkey_alg_flag;
	UINT8		pad[3];  
	para_alg	pubkey_para;
	UINT8		pubkey_data[MAX_BYTE_DATA_LEN];
}__ATTRIBUTE_PACK__;
typedef struct _pubkey_data pubkey_data;

struct _extension_attr_tlv{
 	UINT8 	tlv_type;
	UINT8 	pad[3];
	UINT16	tlv_len; 
	UINT16  pad16[2];
	UINT8  	tlv_data[MAX_BYTE_DATA_LEN];
}__ATTRIBUTE_PACK__;
typedef struct _extension_attr_tlv extension_attr_tlv; 

struct _certificate {
	UINT16		version;
	UINT16		pad_value;
	UINT8		serial_number[4];
	byte_data 	issure_name;
	pov			validity;
	byte_data 	subject_name;
	pubkey_data	subject_pubkey;
	UINT8		extension; 
	UINT8		pad[3];
	extension_attr_tlv	attr_tlv[MAX_EXTENSION_TLV_ATTR];
	wai_fixdata_alg		sign_alg;
	comm_data 	signature;
} __ATTRIBUTE_PACK__;

typedef struct _certificate certificate, *pcertificate;

 struct _packet_head {
	UINT16	version;
	UINT8	type;
	UINT8	sub_type;
	UINT16	reserved;
	UINT16	data_len;
	UINT16	group_sc;
	UINT8	frame_sc;
	UINT8	flag;
} __ATTRIBUTE_PACK__;
typedef struct _packet_head packet_head, *ppacket_head;

struct _attribute {
	UINT16	identifier;
	UINT16 	length;
	UINT8  	data[MAX_BYTE_DATA_LEN];	 
} __ATTRIBUTE_PACK__;
typedef struct _attribute attribute;

 struct _auth_active {
 	wai_fixdata_flag	flag;
	UINT8				pad_vlue[3];
	UINT8				ae_auth_flag[32];
	wai_fixdata_id		asu_id;
	wai_fixdata_cert 	ae_cer;
	para_alg			ecdh;
	//wai_attridata_alg_list       alg_list;
} __ATTRIBUTE_PACK__;
typedef struct _auth_active    auth_active,  *pauth_active;
typedef auth_active Tactivate_mt_auth, *LPTactivate_mt_auth;      

struct _access_auth_request {
	wai_fixdata_flag	flag;
	UINT8				ae_auth_flag[32];
	UINT8				asue_challenge[32];
	byte_data			key_data;
	wai_fixdata_id		ae_id;
	wai_fixdata_cert	asue_cert;
	wai_attridata_id_list	asu_id_list;
	para_alg			ecdh;
	//wai_attridata_alg_list		asue_alg_list;
	wai_attridata_auth_payload	asue_sign;
} __ATTRIBUTE_PACK__;
typedef struct _access_auth_request    access_auth_request;

struct _cert_check_result {
	wai_attridata_auth_result 		cert_result;
	wai_attridata_auth_payload	asue_trust_asu_sign;
	wai_attridata_auth_payload	ae_trust_asu_sign;
}__ATTRIBUTE_PACK__;
typedef struct _cert_check_result cert_check_result;

 struct _certificate_auth_response { 
	wai_fixdata_addid	addid;
	cert_check_result	cert_result;
} __ATTRIBUTE_PACK__;
typedef struct _certificate_auth_response certificate_auth_response;

struct _wapi_access_auth_rsp
{
	UINT8				flag;	// bit0: Update BK, bit1: Pre-auth, bit2: Verify Cert, bit3: optional selection, bit4: Update USK, bit5: STAKey negotiation, bit6: STAKey Cancel 
	UINT8				pad_val[3];
	UINT8				asue_challenge[WAPI_NONCE_LEN];
	UINT8				ae_challenge[WAPI_NONCE_LEN];
	UINT8				access_result;
	UINT8				pad_val1[3];
	byte_data			asue_key_data;
	byte_data			ae_key_data;
	wai_fixdata_id		sta_aeId;
	wai_fixdata_id		sta_asueId;
	cert_check_result	cer_valid_result;
	wai_attridata_auth_payload	ae_sign;	// Signature of AE
} __ATTRIBUTE_PACK__;
typedef struct _wapi_access_auth_rsp wapi_access_auth_response;

 struct _issure_cert {
	certificate as_cer;
	certificate user_cer;
	byte_data   user_seckey;
} __ATTRIBUTE_PACK__;
typedef struct _issure_cert issure_cert;

#endif

