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
	config.h
	
	Revision History:
	Who 			When			What
	--------		----------		----------------------------------------------
	Albert Yang		2008/4/10		
	
*/
#include "type_def.h"

typedef struct PACKED _COMMON_WAPI_INFO
{	
	UINT8			wapi_ifname[IFNAMSIZ];		// wai negotiation
	UINT8			wapi_ifname_len;			
	UINT8 			preauth_ifname[IFNAMSIZ];	// pre-authentication
	UINT8			preauth_ifname_len;
	UINT8			as_cert_no;
	UINT8			as_cert_path[MAX_ID_NO][128];			// the path of as certification
	UINT8			as_cert_path_len[MAX_ID_NO];
	UINT8			ca_cert_path[128];			// the path of ca certification
	UINT8			ca_cert_path_len;
	UINT8			user_cert_path[128];		// the path of local user certification 
	UINT8			user_cert_path_len;		
	UINT32			wapi_as_ip;					// the ip address of authentication server
	UINT32			wapi_as_port;				// the port of authentication server
} COMMON_WAPI_INFO, *PCOMMON_WAPI_INFO;

typedef struct PACKED _MBSS_WAPI_INFO
{	
	UINT8			ifname[IFNAMSIZ];
	UINT8			ifname_len;
	UINT8			auth_mode;	
    UINT8       	psk[64];
	UINT8			psk_len;	
	UINT8			wie[128];
	UINT8			wie_len;
} MBSS_WAPI_INFO, *PMBSS_WAPI_INFO;

// It's used by wapi daemon to require relative configuration
typedef struct PACKED _WAPI_CONF
{
	UINT8				mbss_num;
    COMMON_WAPI_INFO	comm_wapi_info;					 	
	MBSS_WAPI_INFO		mbss_wapi_info[MAX_MBSSID_NUM];
} WAPI_CONF, *PWAPI_CONF;

