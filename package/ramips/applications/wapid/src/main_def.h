/*
 ***************************************************************************
 * Ralink Tech Inc.
 * 5F., No.36 Taiyuan St., Jhubei City,
 * Hsin-chu, Taiwan, R.O.C.
 *
 * (c) Copyright 2008, Ralink Technology, Inc.
 *
 * All rights reserved. Ralink's source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of Ralink Tech. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of Ralink Technology, Inc. is obtained.
 ***************************************************************************

	Module Name:
	main_def.h
	
	Revision History:
	Who 			When			What
	--------		----------		----------------------------------------------
	Albert Yang		2008/4/10		WAPI main include
	
*/

#ifndef MAIN_DEF_H
#define MAIN_DEF_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "type_def.h"
#include "common.h"
#include "mlme.h"
#include "wapi.h"
#include "sta_info.h"
#include "eloop.h"
#include "structure.h"

/* It shall be the same with wireless driver */
#define wapid_version	"2.6.0.0"

// IEEE 802.11 OIDs
#if WIRELESS_EXT <= 11
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE                              0x8BE0
#endif
#define SIOCIWFIRSTPRIV								SIOCDEVPRIVATE
#endif

#define	OID_GET_SET_TOGGLE							0x8000 

#define OID_802_11_DEAUTHENTICATION                 0x0526
#define OID_802_11_WAPI_PID							0x06A0
#define OID_802_11_PORT_SECURE_STATE				0x06A1
#define OID_802_11_UCAST_KEY_INFO					0x06A2
#define OID_802_11_MCAST_TXIV						0x06A3
#define OID_802_11_MCAST_KEY_INFO					0x06A4
#define OID_802_11_WAPI_CONFIGURATION				0x06A5
#define OID_802_11_WAPI_IE							0x06A6

#define RT_OID_802_11_DEAUTHENTICATION				(OID_GET_SET_TOGGLE | OID_802_11_DEAUTHENTICATION)
#define RT_OID_802_11_WAPI_PID						(OID_GET_SET_TOGGLE | OID_802_11_WAPI_PID)
#define RT_OID_802_11_PORT_SECURE_STATE				(OID_GET_SET_TOGGLE | OID_802_11_PORT_SECURE_STATE)
#define RT_OID_802_11_UCAST_KEY_INFO				(OID_GET_SET_TOGGLE | OID_802_11_UCAST_KEY_INFO)
#define RT_OID_802_11_MCAST_TXIV					(OID_GET_SET_TOGGLE | OID_802_11_MCAST_TXIV)
#define RT_OID_802_11_MCAST_KEY_INFO				(OID_GET_SET_TOGGLE | OID_802_11_MCAST_KEY_INFO)
#define RT_OID_802_11_WAPI_CONFIGURATION			(OID_GET_SET_TOGGLE | OID_802_11_WAPI_CONFIGURATION)
#define RT_OID_802_11_WAPI_IE						(OID_GET_SET_TOGGLE | OID_802_11_WAPI_IE)


#define RT_PRIV_IOCTL								(SIOCIWFIRSTPRIV + 0x01)

#define TX_BUFFER		2048
#define RX_BUFFER		2048

// Reason code definitions
#define REASON_WAI_UCAST_HS_TIMEOUT    		25
#define REASON_WAI_MCAST_HS_TIMEOUT    		26
#define REASON_WAI_WIE_MISMATCH    			27
#define REASON_WAI_INVALID_G_CIPHER    		28
#define REASON_WAI_INVALID_P_CIPHER    		29
#define REASON_WAI_WIE_VERS_NOT_SUPPORT    	30
#define REASON_WAI_INVALID_WIE_CAP    		31
#define REASON_WAI_CERT_AUTH_FAIL    		32

// Certificate mode
#define TWO_CERTIFICATE_MODE    		1 /* user, as */
#define THREE_CERTIFICATE_MODE    		2 /* user, as, ca */

#define ID_LIST		3

typedef struct PACKED _IEEE_8023_HDR {
	UCHAR 	DAddr[MAC_ADDR_LEN];
	UCHAR 	SAddr[MAC_ADDR_LEN];
	USHORT 	ether_type;
} IEEE_8023_HDR, *PIEEE_8023_HDR;

typedef struct PACKED _MSK_INFO {
	UINT32 	keyIdx;
	UCHAR 	NMK[16];
} MSK_INFO, *PMSK_INFO;

struct wapi_auth_server {
	struct in_addr as_addr;
	int as_port;
};

struct wapi_device_config
{
	
	char cert_name[256];
	int  as_no;
	char as_name[MAX_ID_NO][256];
	char ca_name[256];
	char ae_name[256];
	unsigned short used_cert; /* 0: NOT used, 1:x509, 2:GBW */
	//unsigned short pad;
	unsigned short cert_mode; /* 1: 2 certicicates, 2: 3 certificates */
};
struct _wapi_cert_info {
	struct cert_obj_st_t *local_cert_obj;
	struct wapi_device_config config;
};

typedef struct _MULTI_BSS {	
	UCHAR								wlan_addr[MAC_ADDR_LEN];

	UCHAR								ifname[IFNAMSIZ+1];
	UCHAR								ifname_len;
    
	// the cipher setting
	WAPI_AUTH_MODE     					AuthMode;			// authentication type
	WAPI_ENCRYPTION_TYPE				UniEncrypType;		// the encryption type of unicast key 	
	WAPI_ENCRYPTION_TYPE				MultiEncrypType;	// the encryption type of multicast key 
	UCHAR								MSKID;				// the multicast key index

	UCHAR								WAPI_PSK[64];		// the pre-shared key 	
	UINT32								WAPI_PSK_len;		// the length of the pre-shared key 	
	UCHAR								BK[16];

	//UCHAR								pad[2];
	UCHAR								NMK[16];			// notify master key(NMK).
	UCHAR								KeyNotifyIv[16];	
	//UCHAR								GTK[32];
	
	// indicate the pre-authentication
    BOOLEAN                             PreAuth;

	// WAPI information element
    UCHAR                               WIE_Len;
    UCHAR                               WIE[MAX_LEN_OF_WIE];

} MULTI_BSS, *PMULTI_BSS;


typedef struct _RTMP_ADAPTER 
{
	INT 			wlan_sock;						// raw packet socket for wireless interface access		
	INT 			eth_sock; 						// raw packet socket for ethernet interface access
	INT 			ioctl_sock; 					// socket for ioctl() using
	INT				as_udp_sock;					// udp socket for authentication server messages
	UCHAR			l2_addr[MAC_ADDR_LEN];						
	USHORT			l2_mtu;							

	// working interface
	UCHAR			wapi_ifname[IFNAMSIZ];
	UCHAR 			preauth_ifname[IFNAMSIZ];			

	// fragmented frame
	PUCHAR			FragFrame;				// store the received frame for defragment process
	UINT32			TotalFragLen;

	MLME_STRUCT		Mlme;						
	STA_TABLE		StaTab;

	INT				mbss_num;
	MULTI_BSS    	MBSS[MAX_MBSSID_NUM];

	UCHAR			WAPI_CERT_INDEX;	// /*1:x509 2:GBW */
	UCHAR			WAPI_ASU_IP[20];
	UCHAR			WAPI_ASU_PORT[20];
	struct wapi_auth_server auth_server;
	struct _wapi_cert_info 	cert_info;	// Certificate info
	wai_fixdata_alg		sign_alg;	// Signature algorithm
	wai_fixdata_id		local_user_id;	// Local user Identity
	wai_fixdata_id		ca_id;	// CA Identity
	wai_fixdata_id		asu_id[MAX_ID_NO];	// ASU's Identity
	para_alg			local_ecdh; // Local ECDH parameter

} RTMP_ADAPTER, *PRTMP_ADAPTER;

// Define in main.c
void wapi_trigger_sm_timeout(
		PRTMP_ADAPTER pAd, 
		PSTA_TABLE_ENTRY pEntry);

BOOLEAN wapi_handle_l2_send(
		PRTMP_ADAPTER 		pAd, 
		PSTA_TABLE_ENTRY	pEntry,
		UCHAR				MsgType,
		UCHAR 				*Msg, 
		INT    				MsgLen);

VOID wapi_set_ucast_key_proc(
	PRTMP_ADAPTER		pAd,
	PSTA_TABLE_ENTRY	pEntry);

VOID wapi_set_mcast_key_info(
	PRTMP_ADAPTER		pAd,
	UCHAR				apidx,
	PUCHAR				mkey_info_ptr);

VOID wapi_set_port_secured_proc(
	PRTMP_ADAPTER		pAd,
	PSTA_TABLE_ENTRY	pEntry);

BOOLEAN wapi_get_mcast_tx_iv(
	IN	PRTMP_ADAPTER	pAd,
	IN	UCHAR			apidx,
	OUT	PUCHAR			pTxIv);

BOOLEAN wapi_get_wie(
	IN  PRTMP_ADAPTER		pAd,
	IN	UCHAR				apidx,
	IN	PUCHAR				pAddr,
	OUT	PWAPI_WIE_STRUCT	wie_ptr);

BOOLEAN wapi_get_mcast_key_info(
	IN  PRTMP_ADAPTER		pAd,
	IN	UCHAR				apidx,
	OUT	PUCHAR				mkey_info_ptr);

VOID DisconnectStaLink(
	IN PRTMP_ADAPTER	pAd,
	IN INT				wcid,
	IN USHORT			reason);

SHORT wapi_client_send(
		PRTMP_ADAPTER 		pAd, 
		PSTA_TABLE_ENTRY	pEntry,
		UCHAR				MsgType,
		PUCHAR 				pMsg, 
		INT    				MsgLen);

int RT_ioctl(
		INT 	sid, 
		INT 	param, 
		PUCHAR 	pData, 
		UINT 	data_len, 
		PUCHAR 	pIfName, 
		UCHAR 	ifNameLen, 
		INT 	flags);

// Define in mlme.c
NDIS_STATUS MlmeInit(
	PRTMP_ADAPTER pAd);

VOID MlmeHalt(
	PRTMP_ADAPTER pWd);

VOID StateMachineInit(
	IN STATE_MACHINE *S, 
	IN STATE_MACHINE_FUNC Trans[], 
	IN ULONG StNr,
	IN ULONG MsgNr,
	IN STATE_MACHINE_FUNC DefFunc, 
	IN ULONG InitState, 
	IN ULONG Base);

VOID StateMachineSetAction(
	IN STATE_MACHINE *S, 
	IN ULONG St, 
	IN ULONG Msg, 
	IN STATE_MACHINE_FUNC Func);

VOID Drop(
    IN PRTMP_ADAPTER 	Ad,
    IN MLME_QUEUE_ELEM *Elem);

BOOLEAN MlmeEnqueue(
	PRTMP_ADAPTER	pAd,
	ULONG 		Machine, 
	ULONG 		MsgType, 
	ULONG 		Wcid,
	ULONG 		MsgLen, 
	VOID 		*Msg);

BOOLEAN MlmeEnqueueForRecv(
	PRTMP_ADAPTER	pAd, 
	ULONG Wcid,
	ULONG MsgLen, 
	VOID *Msg);

// Define in wapi.c
VOID WAIAuthStateMachineInit(
	IN PRTMP_ADAPTER pWd,
	IN STATE_MACHINE *Sm,
	OUT STATE_MACHINE_FUNC Trans[]);

VOID WAIKeyStateMachineInit(
	IN PRTMP_ADAPTER pWd,
	IN STATE_MACHINE *Sm,
	OUT STATE_MACHINE_FUNC Trans[]);

const char *GetWaiMsgTypeText(CHAR msgType);

const char *GetWaiKeyStateText(ULONG state);

VOID MakeWaiHeader(	
	IN	UCHAR		SubType,
	IN	USHORT		FrameLen,
	IN	USHORT		FrameSeq,
	IN	UCHAR		FragSeq,
	IN	BOOLEAN		bMoreFrag,
	OUT PHEADER_WAI	pHdr);

// Define in sta_info.c
STA_TABLE_ENTRY *StaTableLookup(
	IN PRTMP_ADAPTER 	pAd, 
	IN PUCHAR 			pAddr);

STA_TABLE_ENTRY *StaTableInsertEntry(
	IN  PRTMP_ADAPTER   pAd, 
	IN  PUCHAR			pAddr,
	IN	UCHAR			apidx);

BOOLEAN StaTableDeleteEntry(
	IN PRTMP_ADAPTER pAd, 
	IN USHORT wcid,
	IN PUCHAR pAddr);

VOID StaTableReset(
	IN  PRTMP_ADAPTER  pAd);

// Define in config.c
BOOLEAN config_read(
	IN PRTMP_ADAPTER 	pAd,
	IN PUCHAR			pIfName,
	IN INT				ifname_len);

BOOLEAN ap_initialize_signature_alg(
	IN PRTMP_ADAPTER pAd);

// Define in cert_auth.c
USHORT wapi_auth_activate_create(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	sendto_asue);

SHORT wapi_auth_activate_check(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	recvfrom_ae,
		IN USHORT	recvfrom_ae_len);

USHORT wapi_access_auth_request_create(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	sendto_ae);

SHORT wapi_access_auth_request_check(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	recvfrom_asue,
		IN USHORT	recvfrom_asue_len);

USHORT wapi_certificate_auth_request_create(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	sendto_as);

SHORT wapi_certificate_auth_response_check(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	recvfrom_as,
		IN USHORT	recvfrom_as_len,
		OUT PUCHAR	ecdhKey);

USHORT wapi_access_auth_response_create(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	sendto_asue,
		IN PUCHAR	recvfrom_as,
		IN USHORT	recvfrom_as_len);

SHORT wapi_access_auth_response_check(
		IN PRTMP_ADAPTER	pAd,
		IN PUCHAR	pAddr,
		IN PUCHAR	recvfrom_ae,
		IN USHORT	recvfrom_ae_len,
		OUT PUCHAR	ecdhKey);

SHORT pack_auth_active(
		auth_active* pContent,
		PUCHAR buffer,
		USHORT *buffer_len,
		USHORT bufflen);

SHORT pack_access_auth_request(
		PRTMP_ADAPTER pAd,
		const access_auth_request* pContent,
		PUCHAR buffer,
		USHORT buffer_len,
		USHORT bufflen);

SHORT pack_certificate_auth_request(
		PRTMP_ADAPTER pAd,
		const struct _access_auth_request *pContent,
		void* buffer,
		USHORT buffer_len,
		USHORT bufflen);


#endif // MAIN_DEF_H //
