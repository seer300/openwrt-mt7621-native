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
	sta_info.h
	
	Revision History:
	Who 			When			What
	--------		----------		----------------------------------------------
	Albert Yang		2008/4/15		STA INFO definition
	
*/

#ifndef STA_INFO_H
#define STA_INFO_H

#include "structure.h"

#define HASH_TABLE_SIZE                 256
#define MAX_STA_NUM						32

#define MAC_ADDR_HASH(Addr)            (Addr[0] ^ Addr[1] ^ Addr[2] ^ Addr[3] ^ Addr[4] ^ Addr[5])
#define MAC_ADDR_HASH_INDEX(Addr)      (MAC_ADDR_HASH(Addr) % HASH_TABLE_SIZE)

#define VALID_WCID(_wcid)	((_wcid) > 0 && (_wcid) < MAX_STA_NUM)

typedef struct _STA_TABLE_ENTRY {
	struct _STA_TABLE_ENTRY *pNext;
	BOOLEAN			Valid;	
	UCHAR			Addr[MAC_ADDR_LEN];			// the STA's mac address	
	USHORT			Aid;						// the associated ID

	// the WAI state
	ULONG			WaiAuthState;				// indicate the WAI authentication state
	ULONG			WaiKeyState;				// indicate the WAI key negotiation state

	WAPI_AUTH_MODE     			AuthMode;			// authentication type
	WAPI_ENCRYPTION_TYPE		UniEncrypType;		// the encryption type of unicast key 	
	WAPI_ENCRYPTION_TYPE		MultiEncrypType;	// the encryption type of multicast key 
		
	UCHAR           apidx;						// MBSS number 		
	UCHAR         	PortSecured;				// the control port state, 
												// 0 indicates NOT secured
												// 1 indicates secured
												
	UCHAR			BK[16];						// the base key
	UCHAR			BKID[16];					// the identifier of BK 
	UCHAR			BK_AUTH_ID[NONCE_LEN];		// BK authentication ID for BK update

	UCHAR			id_flag;					// Identification flag defined in 5.2.1.4.1.1 (a)
	UCHAR			AUTH_ID[NONCE_LEN];			// authenticate identification
		
	UCHAR			ANONCE[NONCE_LEN];			// AE Challenge
	UCHAR			SNONCE[NONCE_LEN];			// ASUE Challenge

	UCHAR			ADDID[12];					// AE_MAC || ASUE_MAC 

	UCHAR			USKID;						// unicast key index; 
	UCHAR			PTK[96];					// unicast and additional key, nonce
	UCHAR			PTK_SEED[NONCE_LEN];		// the seed of PTK

	UCHAR			retry_cnt;					// the retry count of key handshaking	
	UINT16			frame_seq;					// the frame sequence of WAI header

#if 0 // test only
	// WAPI information element
    UCHAR           WIE_Len;
    UCHAR           WIE[MAX_LEN_OF_WIE];


	UCHAR			Flag;
	UCHAR			asue_nonce[32];				// the asue nonce of WAI handshaking
	UCHAR			ae_nonce[32];				// the AE nonce of WAI handshaking
#endif
	UCHAR			asue_cert_hash[32];			// the asue cert hash
	tkey			private_key;				// the temp private key of WAI handshaking
	byte_data		asue_key_data;				// the asue temp public key of WAI handshaking
	byte_data		ae_key_data;				// the ae temp public key of WAI handshaking
	para_alg  		ecdh;						// the ECDH alg parameter
	wai_fixdata_id	asu_id;						// the asu id
	wai_fixdata_id	user_id;					// the user id
	wai_temp_fixdata_cert	user_cert;			// the user certificate
	UINT8			asue_auth_result;
	wai_attridata_id_list	asu_id_list;
	
} STA_TABLE_ENTRY, *PSTA_TABLE_ENTRY;


typedef struct _STA_TABLE {
	USHORT			Size;
	STA_TABLE_ENTRY *Hash[HASH_TABLE_SIZE];
	STA_TABLE_ENTRY Content[MAX_STA_NUM];	
} STA_TABLE, *PSTA_TABLE;

#endif // STA_INFO_H //

