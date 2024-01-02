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
	wapi_main.c
	
	Revision History:
	Who 			When			What
	--------		----------		----------------------------------------------
	Albert Yang		2008/4/10		WAPI main include
	
*/

#ifndef WAPI_H
#define WAPI_H

#ifndef ETH_P_WAPI
#define ETH_P_WAPI 0x88B4 
#endif // ETH_P_WAPI //

#ifndef ETH_P_VLAN
#define ETH_P_VLAN 0x8100 /* VLAN Protocol */
#endif /* ETH_P_VLAN */

#define LENGTH_HEADER_WAI		12
#define MAX_WAI_KEY_HS_LEN		256
#define MAX_WAI_AUTH_HS_LEN		4096
#define LEN_MSG_AUTH_CODE		20
#define LEN_TX_IV				16

// WIE Length definition
#define MAX_LEN_OF_WIE         	90
#define MIN_LEN_OF_WIE         	8

// trigger message from driver
#define WAI_MLME_CERT_AUTH_START	1
#define WAI_MLME_KEY_HS_START		2
#define WAI_MLME_UPDATE_BK			3
#define WAI_MLME_UPDATE_USK			4
#define WAI_MLME_UPDATE_MSK			5

// the version of WAI protocol header
#define WAI_PROTOCOL_VERS	1

// the type of the WAI protocol header
#define WAI_PROTOCOL_TYPE	1

// the sub-type of the WAI protocol header
#define WAI_PREAUTH_MSG				1
#define WAI_STAKEY_REQ_MSG			2
#define WAI_AUTH_ACTIVATE_MSG		3
#define WAI_ACCESS_AUTH_REQ_MSG		4
#define WAI_ACCESS_AUTH_RESP_MSG	5
#define WAI_CERT_AUTH_REQ_MSG		6
#define WAI_CERT_AUTH_RESP_MSG		7
#define WAI_UNI_KEY_REQ_MSG			8
#define WAI_UNI_KEY_RESP_MSG		9
#define WAI_UNI_KEY_CONFIRM_MSG		10
#define WAI_MULTI_KEY_NOTIFY_MSG	11
#define WAI_MULTI_KEY_RESP_MSG		12

// the flag of WAI data 
#define WAI_FLAG_BK_UPDATE 			BIT(0)
#define WAI_FLAG_PRE_AUTH 			BIT(1)
#define WAI_FLAG_CERT_REQ 			BIT(2)
#define WAI_FLAG_OPTION 			BIT(3)
#define WAI_FLAG_USK_UPDATE 		BIT(4)
#define WAI_FLAG_STAKEY_HS			BIT(5)
#define WAI_FLAG_STAKEY_DEL			BIT(6)
#define WAI_FLAG_RESV				BIT(7)


#define WAI_FLAG_BK_RENEW_IS_ON(x)		(((x) & 0x01) != 0)
#define WAI_FLAG_PRE_AUTH_IS_ON(x)		(((x) & 0x02) != 0)
#define WAI_FLAG_CERT_REQ_IS_ON(x)		(((x) & 0x04) != 0)
#define WAI_FLAG_OPTION_IS_ON(x)		(((x) & 0x08) != 0)
#define WAI_FLAG_USK_RENEW_IS_ON(x)		(((x) & 0x10) != 0)
#define WAI_FLAG_STAKEY_HS_IS_ON(x)		(((x) & 0x20) != 0)
#define WAI_FLAG_STAKEY_DEL_IS_ON(x)	(((x) & 0x40) != 0)

// The port secure flag
#define PORT_SECURE_RX_IS_ON(x)			(((x) & 0x01) != 0)
#define PORT_SECURE_TX_IS_ON(x)			(((x) & 0x02) != 0)

// Retry counter of certificate authentication
#define AUTH_CERT_IDLE_CTR           0		// initial value 
#define AUTH_WAIT_ACS_REQ_CTR      	10		// AE re-tramsnit auth-activate frame(3)
#define AUTH_WAIT_CERT_RESP_CTR     20		// AE re-transmit cert-auth-req frame(6)		
#define AUTH_WAIT_ACS_RESP_CTR     	30		// ASUE re-transmit accsee-auth-req frame(4) 
#define AUTH_CERT_DONE_CTR			40		// certificate complete

// Retry counter of key negotiation
#define UCAST_IDLE_CTR           	0		// initial value
#define UCAST_WAIT_RESP_CTR      	10		// AE re-transmit ucast-key-req frame(8)
#define UCAST_WAIT_CFM_CTR       	20		// ASUE re-transmit ucast-key-resp frame(9)
#define UCAST_DONE_CTR				30		// ucast key HS complete
#define MCAST_WAIT_RESP_CTR			40		// AE re-transmit mcast-key-notify frame(11)

typedef enum _WAPI_PORT_SECURE_STATE
{
   WAPI_PORT_NOT_SECURED,
   WAPI_PORT_SECURED,
} WAPI_PORT_SECURE_STATE, *PWAPI_PORT_SECURE_STATE;

typedef struct _WAPI_PORT_SECURE_STRUCT {
    UCHAR       Addr[MAC_ADDR_LEN];
    USHORT      state;
} WAPI_PORT_SECURE_STRUCT, *PWAPI_PORT_SECURE_STRUCT;

typedef struct _WAPI_UCAST_KEY_STRUCT {
    UCHAR       Addr[MAC_ADDR_LEN];
	USHORT		key_id;
    UCHAR		PTK[64];					// unicast and additional key
} WAPI_UCAST_KEY_STRUCT, *PWAPI_UCAST_KEY_STRUCT;

typedef struct _WAPI_MCAST_KEY_STRUCT {    
	UINT32		key_id;
	UCHAR		m_tx_iv[16];
	UCHAR		key_announce[16];
    UCHAR		NMK[16];					// notify master key
} WAPI_MCAST_KEY_STRUCT, *PWAPI_MCAST_KEY_STRUCT;

typedef struct _WAPI_WIE_STRUCT {    
	UCHAR		addr[MAC_ADDR_LEN];
	UINT32		wie_len;
    UCHAR		wie[MAX_LEN_OF_WIE];					// wapi information element
} WAPI_WIE_STRUCT, *PWAPI_WIE_STRUCT;

// WAPI authentication mode
typedef enum _WAPI_AUTH_MODE
{
   WAPI_AUTH_DISABLE,
   WAPI_AUTH_PSK,
   WAPI_AUTH_CERT,
} WAPI_AUTH_MODE, *PWAPI_AUTH_MODE;

// WAPI encryption type
typedef enum _WAPI_ENCRYPTION_TYPE
{
   WAPI_ENCRYPT_DISABLE,
   WAPI_ENCRYPT_SMS4,
} WAPI_ENCRYPTION_TYPE, *PWAPI_ENCRYPTION_TYPE;

typedef	struct PACKED _HEADER_WAI	{    
    USHORT          version;
	UCHAR			type;
	UCHAR			sub_type;
	USHORT			reserved;
	USHORT			length;
	USHORT			pkt_seq;
	UCHAR			frag_seq;
	UCHAR			flag;
}	HEADER_WAI, *PHEADER_WAI;

// the structure of the unicast key negotiation request frame
typedef	struct PACKED _UCAST_KEY_REQ_FRAME	{        
	UCHAR			Flag;
	UCHAR			BKID[16];
	UCHAR			USKID;
	UCHAR			ADDID[12];
	UCHAR			AE_CHALLENGE[NONCE_LEN];				
}	UCAST_KEY_REQ_FRAME, *PUCAST_KEY_REQ_FRAME;

// the structure of the unicast key negotiation response frame
typedef	struct PACKED _UCAST_KEY_RESP_FRAME	{        
	UCHAR			Flag;
	UCHAR			BKID[16];
	UCHAR			USKID;
	UCHAR			ADDID[12];
	UCHAR			ASUE_CHALLENGE[NONCE_LEN];	
	UCHAR			AE_CHALLENGE[NONCE_LEN];	
	UCHAR			WIE[0];
}	UCAST_KEY_RESP_FRAME, *PUCAST_KEY_RESP_FRAME;

// the structure of the unicast key negotiation confirm frame
typedef	struct PACKED _UCAST_KEY_CFM_FRAME	{        
	UCHAR			Flag;
	UCHAR			BKID[16];
	UCHAR			USKID;
	UCHAR			ADDID[12];
	UCHAR			ASUE_CHALLENGE[NONCE_LEN];
	UCHAR			WIE[0];
}	UCAST_KEY_CFM_FRAME, *PUCAST_KEY_CFM_FRAME;

// the structure of the multicast key negotiation notify frame
typedef	struct PACKED _MCAST_KEY_NOTIFY_FRAME	{        
	UCHAR			Flag;
	UCHAR			MSKID;
	UCHAR			USKID;
	UCHAR			ADDID[12];
	UCHAR			GROUP_TX_IV[LEN_TX_IV];
	UCHAR			KEY_NOTIFY_IV[LEN_TX_IV];	
	UCHAR			data[0];
}	MCAST_KEY_NOTIFY_FRAME, *PMCAST_KEY_NOTIFY_FRAME;

// the structure of the multicast key negotiation response frame
typedef	struct PACKED _MCAST_KEY_RESP_FRAME	{        
	UCHAR			Flag;
	UCHAR			MSKID;
	UCHAR			USKID;
	UCHAR			ADDID[12];
	UCHAR			KEY_NOTIFY_IV[LEN_TX_IV];
	UCHAR			MAC[LEN_MSG_AUTH_CODE];
}	MCAST_KEY_RESP_FRAME, *PMCAST_KEY_RESP_FRAME;

#endif // WAPI_H //

