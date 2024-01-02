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
	mlme.h
	
	Revision History:
	Who 			When			What
	--------		----------		----------------------------------------------
	Albert Yang		2008/4/10		WAPI mlme state machine
	
*/



#define MAX_LEN_OF_MLME_QUEUE       20
//#define MAX_BUFFER_SIZE    			2500
#define MAX_BUFFER_SIZE    			3000
#define RESERVED_WCID				0xff

// ========================================================
// WAI state machine definition
// ========================================================
#define WAI_AUTH_STATE_MACHINE			1
#define WAI_KEY_STATE_MACHINE			2

// WAI state machine
// WAI authenticate state type
#define WAI_CERT_AUTH_IDLE				0
#define WAI_WAIT_ACCESS_AUTH_REQ		1
#define WAI_WAIT_ACCESS_AUTH_RESP		2
#define WAI_WAIT_CERT_AUTH_RESP			3
#define WAI_CERT_AUTH_DONE				4
#define WAI_AUTH_MAX_STATE				5

// WAI authenticate message type
#define WAI_AUTH_MESSAGE_BASE			0
#define WAI_MLME_AUTH_ACTIVATE			0
#define WAI_PEER_AUTH_ACTIVATE			1
#define WAI_MLME_ACS_AUTH_REQ			2
#define WAI_PEER_ACS_AUTH_REQ			3
#define WAI_MLME_CERT_AUTH_REQ			4
#define WAI_PEER_CERT_AUTH_REQ			5
#define WAI_MLME_CERT_AUTH_RESP			6
#define WAI_PEER_CERT_AUTH_RESP			7
#define WAI_MLME_ACS_AUTH_RESP			8
#define WAI_PEER_ACS_AUTH_RESP			9
#define WAI_AUTH_MAX_MSG				10

#define WAI_AUTH_FUNC_SIZE               (WAI_AUTH_MAX_STATE * WAI_AUTH_MAX_MSG)

// WAI key negotiation state type
#define WAI_UCAST_KEY_IDLE				0
#define WAI_WAIT_UCAST_RESP				1
#define WAI_WAIT_UCAST_CFM				2
#define WAI_UCAST_KEY_DONE				3
#define WAI_WAIT_MCAST_RESP				4
#define WAI_MCAST_KEY_DONE				5
#define WAI_KEY_MAX_STATE				6


// WAI key negotiation message type
#define WAI_KEY_MESSAGE_BASE			0
#define WAI_MLME_UCAST_KEY_REQ			0
#define WAI_PEER_UCAST_KEY_REQ			1
#define WAI_MLME_UCAST_KEY_RESP			2
#define WAI_PEER_UCAST_KEY_RESP			3
#define WAI_PEER_UCAST_KEY_CFM			4
#define WAI_MLME_MCAST_KEY_NOTIFY		5
#define WAI_PEER_MCAST_KEY_NOTIFY		6
#define WAI_PEER_MCAST_KEY_RESP			7
#define WAI_KEY_MAX_MSG					8

#define WAI_KEY_FUNC_SIZE               (WAI_KEY_MAX_STATE * WAI_KEY_MAX_MSG)

typedef struct _MLME_DEAUTH_REQ_STRUCT {
    UCHAR        Addr[MAC_ADDR_LEN];
    USHORT       Reason;
} MLME_DEAUTH_REQ_STRUCT, *PMLME_DEAUTH_REQ_STRUCT;

typedef struct _MLME_QUEUE_ELEM {
    ULONG             Machine;
    ULONG             MsgType;
    ULONG             MsgLen;
    UCHAR             Msg[MAX_BUFFER_SIZE];      
    UCHAR             Wcid;
    BOOLEAN           Occupied;
} MLME_QUEUE_ELEM, *PMLME_QUEUE_ELEM;

typedef struct _MLME_QUEUE {
    ULONG             	Num;
    ULONG             	Head;
    ULONG             	Tail;    
    MLME_QUEUE_ELEM  	Entry[MAX_LEN_OF_MLME_QUEUE];
} MLME_QUEUE, *PMLME_QUEUE;

typedef VOID (*STATE_MACHINE_FUNC)(VOID *Adaptor, MLME_QUEUE_ELEM *Elem);

typedef struct _STATE_MACHINE
{
	ULONG					Base;
	ULONG					NrState;
	ULONG					NrMsg;
	ULONG					CurrState;
	STATE_MACHINE_FUNC	*TransFunc;
} STATE_MACHINE, *PSTATE_MACHINE;

typedef struct _MLME_STRUCT {

	STATE_MACHINE       WAIAuthStateMachine;	
	STATE_MACHINE_FUNC  WAIAuthStateMachineFunc[WAI_AUTH_FUNC_SIZE];

	STATE_MACHINE       WAIKeyStateMachine;	
	STATE_MACHINE_FUNC  WAIKeyStateMachineFunc[WAI_KEY_FUNC_SIZE];

	BOOLEAN                 bRunning;
	MLME_QUEUE              Queue;

} MLME_STRUCT, *PMLME_STRUCT;

