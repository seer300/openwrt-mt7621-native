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
    wapi.c

    Revision History:
    Who             When            What
    --------        ----------      ----------------------------------------------
    Albert Yang     2008/4/10       WAPI main routine

*/
#include <netinet/in.h>
#include "main_def.h"
#include "sha256.h"
#include "sms4.h"
#include "wpi_pcrypt.h"

static const char group_prefix[100] = "multicast or station key expansion for station unicast and multicast and broadcast";

VOID WaiDump(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

#ifdef OPENSSL_INC
VOID WaiMlmeAuthActivateAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiMlmeCertAuthReqAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerAccessAuthReqAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerCertAuthRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerAuthActivateAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiMlmeAccessAuthReqAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerAccessAuthRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem);

#endif // OPENSSL_INC //

VOID WaiMlmeUcastKeyReqAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerUcastKeyReqAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiMlmeUcastKeyRespAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerUcastKeyRespAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerUcastKeyCfmAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiMlmeMcastKeyNotifyAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerMcastKeyRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID WaiPeerMcastKeyNotifyAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem);

VOID CalculatePairWiseKey(
    IN OUT PSTA_TABLE_ENTRY     pEntry);

#ifdef OPENSSL_INC
/*
    ==========================================================================
    Description:
        WAI state machine init, including state transition and timer init
    Parameters:
        Sm - pointer to the WAI state machine
    Note:

    ==========================================================================
 */

VOID WAIAuthStateMachineInit(
    IN PRTMP_ADAPTER pAd,
    IN STATE_MACHINE *Sm,
    OUT STATE_MACHINE_FUNC Trans[])
{
    StateMachineInit(Sm, (STATE_MACHINE_FUNC*)Trans, WAI_AUTH_MAX_STATE, WAI_AUTH_MAX_MSG, (STATE_MACHINE_FUNC)Drop, WAI_CERT_AUTH_IDLE, WAI_AUTH_MESSAGE_BASE);

    // the first column - WAI_CERT_AUTH_IDLE state
    // 1. AE transmit auth-activate frame to ASUE or
    // 2. ASUE receive auth-activate frame form AE or
    StateMachineSetAction(Sm, WAI_CERT_AUTH_IDLE, WAI_MLME_AUTH_ACTIVATE, (STATE_MACHINE_FUNC)WaiMlmeAuthActivateAction);
    StateMachineSetAction(Sm, WAI_CERT_AUTH_IDLE, WAI_PEER_AUTH_ACTIVATE, (STATE_MACHINE_FUNC)WaiPeerAuthActivateAction);

    // the second column - WAI_WAIT_ACCESS_AUTH_REQ state
    // 1. AE receive access-auth-req frame from ASUE or
    // 2. AE re-transmit auth-activate frame to ASUE.
    StateMachineSetAction(Sm, WAI_WAIT_ACCESS_AUTH_REQ, WAI_PEER_ACS_AUTH_REQ, (STATE_MACHINE_FUNC)WaiPeerAccessAuthReqAction);
    StateMachineSetAction(Sm, WAI_WAIT_ACCESS_AUTH_REQ, WAI_MLME_AUTH_ACTIVATE, (STATE_MACHINE_FUNC)WaiMlmeAuthActivateAction);

    // the third column - WAI_WAIT_ACCESS_AUTH_RESP state
    // 1. ASUE receive access-auth-resp frame from AE or
    // 2. ASUE re-transmit access-auth-req frame to AE or
    // 3. ASUE receive auth-activate frame from AE again.
    StateMachineSetAction(Sm, WAI_WAIT_ACCESS_AUTH_RESP, WAI_PEER_ACS_AUTH_RESP, (STATE_MACHINE_FUNC)WaiPeerAccessAuthRespAction);
    StateMachineSetAction(Sm, WAI_WAIT_ACCESS_AUTH_RESP, WAI_MLME_ACS_AUTH_REQ, (STATE_MACHINE_FUNC)WaiMlmeAccessAuthReqAction);
    StateMachineSetAction(Sm, WAI_WAIT_ACCESS_AUTH_RESP, WAI_PEER_AUTH_ACTIVATE, (STATE_MACHINE_FUNC)WaiPeerAuthActivateAction);

    // the fourth column - WAI_WAIT_CERT_AUTH_RESP state
    // 1. AE receive cert-auth-resp frame from AS or
    // 2. AE re-transmit cert-auth-req frame to AS.
    StateMachineSetAction(Sm, WAI_WAIT_CERT_AUTH_RESP, WAI_PEER_CERT_AUTH_RESP, (STATE_MACHINE_FUNC)WaiPeerCertAuthRespAction);
    StateMachineSetAction(Sm, WAI_WAIT_CERT_AUTH_RESP, WAI_MLME_CERT_AUTH_REQ, (STATE_MACHINE_FUNC)WaiMlmeCertAuthReqAction);

    // the fifth column - WAI_CERT_AUTH_DONE state
    // 1. AE trigger BK update procedure.
    //    - AE send auth-activate frame to ASUE
    //    - ASUE receive auth-activate frame from AE
    // 2. ASUE trigger BK update procedure. AE would receive access-auth-req frame without auth-activate frame.
    //    - ASUE send access-auth-req frame to AE
    //    - AE receive access-auth-req frame from ASUE
    StateMachineSetAction(Sm, WAI_CERT_AUTH_DONE, WAI_MLME_AUTH_ACTIVATE, (STATE_MACHINE_FUNC)WaiMlmeAuthActivateAction);
    StateMachineSetAction(Sm, WAI_CERT_AUTH_DONE, WAI_PEER_AUTH_ACTIVATE, (STATE_MACHINE_FUNC)WaiDump);
    StateMachineSetAction(Sm, WAI_CERT_AUTH_DONE, WAI_MLME_ACS_AUTH_REQ, (STATE_MACHINE_FUNC)WaiDump);
    StateMachineSetAction(Sm, WAI_CERT_AUTH_DONE, WAI_PEER_ACS_AUTH_REQ, (STATE_MACHINE_FUNC)WaiPeerAccessAuthReqAction);

    return;
}
#endif // OPENSSL_INC //

/*
    ==========================================================================
    Description:
        WAI state machine init, including state transition and timer init
    Parameters:
        Sm - pointer to the WAI state machine
    Note:

    ==========================================================================
 */

VOID WAIKeyStateMachineInit(
    IN PRTMP_ADAPTER pAd,
    IN STATE_MACHINE *Sm,
    OUT STATE_MACHINE_FUNC Trans[])
{
    StateMachineInit(Sm, (STATE_MACHINE_FUNC*)Trans, WAI_KEY_MAX_STATE, WAI_KEY_MAX_MSG, (STATE_MACHINE_FUNC)Drop, WAI_UCAST_KEY_IDLE, WAI_KEY_MESSAGE_BASE);

    // The first column - idle state of unicast key
    // 1. AE sent unicast key request to initites unicast key handshaking or
    // 2. ASUE received the unicast key request from AE.
    StateMachineSetAction(Sm, WAI_UCAST_KEY_IDLE, WAI_MLME_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyReqAction);
    StateMachineSetAction(Sm, WAI_UCAST_KEY_IDLE, WAI_PEER_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiPeerUcastKeyReqAction);

    // the second column - wait peer response state of unicast key
    StateMachineSetAction(Sm, WAI_WAIT_UCAST_RESP, WAI_MLME_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyReqAction);
    StateMachineSetAction(Sm, WAI_WAIT_UCAST_RESP, WAI_PEER_UCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiPeerUcastKeyRespAction);

    // the third column - wait peer confirm state of unicast key in ASUE
    StateMachineSetAction(Sm, WAI_WAIT_UCAST_CFM, WAI_MLME_UCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyRespAction);
    StateMachineSetAction(Sm, WAI_WAIT_UCAST_CFM, WAI_PEER_UCAST_KEY_CFM, (STATE_MACHINE_FUNC)WaiPeerUcastKeyCfmAction);

    // the fourth column - handle unicast key done state
    // In AE side
    //  1.  AE go into WAI_UCAST_KEY_DONE state, but still received ASUE unicast key response message
    //  2.  AE sends group message 1 after key done
    //  3.  AE trigger USK update procedure.
    // In ASUE side
    //  1.  When ASUE into WAI_UCAST_KEY_DONE state, it received WAI_PEER_MCAST_KEY_NOTIFY frame from AE.
    //  2.  ASUE trigger USK update procedure.
    //  3.  ASUE receive AE's ucast-key-req.
    StateMachineSetAction(Sm, WAI_UCAST_KEY_DONE, WAI_PEER_UCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiPeerUcastKeyRespAction);
    StateMachineSetAction(Sm, WAI_UCAST_KEY_DONE, WAI_MLME_MCAST_KEY_NOTIFY, (STATE_MACHINE_FUNC)WaiMlmeMcastKeyNotifyAction);
    StateMachineSetAction(Sm, WAI_UCAST_KEY_DONE, WAI_MLME_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyReqAction);
    StateMachineSetAction(Sm, WAI_UCAST_KEY_DONE, WAI_PEER_MCAST_KEY_NOTIFY, (STATE_MACHINE_FUNC)WaiPeerMcastKeyNotifyAction);
    StateMachineSetAction(Sm, WAI_UCAST_KEY_DONE, WAI_MLME_UCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyRespAction);
    StateMachineSetAction(Sm, WAI_UCAST_KEY_DONE, WAI_PEER_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiPeerUcastKeyReqAction);

    // the fifth column - WAI_WAIT_MCAST_RESP
    // 1. AE re-transmit m-cast key notify frame
    // 2. AE received the m-cast key response frame form ASUE
    StateMachineSetAction(Sm, WAI_WAIT_MCAST_RESP, WAI_MLME_MCAST_KEY_NOTIFY, (STATE_MACHINE_FUNC)WaiMlmeMcastKeyNotifyAction);
    StateMachineSetAction(Sm, WAI_WAIT_MCAST_RESP, WAI_PEER_MCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiPeerMcastKeyRespAction);

    // the sixth column - WAI_MCAST_KEY_DONE
    // 1. ASUE has sent out the mcast-key-response, but AE doesn't receive it and re-transmit mcast-key-notify.
    // 2. BK update - NOT implement yet
    // 3. USK update
    //    - AE send ucast-key-req to trigger USK update procedure.
    //    - ASUE send ucast-key-resp to trigger USK update procedure.
    //    - ASUE recived ucast-key-req from AE for USK update procedure.
    //    - AE received ucast-key-resp from ASUE for USK update procedure.
    // 4. MSK update
    //    - AE send mcast-key-notify to trigger MSK update procedure.
    //    - ASUE received mcast-key-notify from AE for MSK update procedure.
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_PEER_MCAST_KEY_NOTIFY, (STATE_MACHINE_FUNC)WaiPeerMcastKeyNotifyAction);
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_MLME_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyReqAction);
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_MLME_UCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiMlmeUcastKeyRespAction);
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_PEER_UCAST_KEY_REQ, (STATE_MACHINE_FUNC)WaiPeerUcastKeyReqAction);
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_PEER_UCAST_KEY_RESP, (STATE_MACHINE_FUNC)WaiPeerUcastKeyRespAction);
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_MLME_MCAST_KEY_NOTIFY, (STATE_MACHINE_FUNC)WaiMlmeMcastKeyNotifyAction);
    StateMachineSetAction(Sm, WAI_MCAST_KEY_DONE, WAI_PEER_MCAST_KEY_NOTIFY, (STATE_MACHINE_FUNC)WaiPeerMcastKeyNotifyAction);

    return;
}

/*
    ==========================================================================
    Description:
        The dump function. This is ONLY for testing.
    ==========================================================================
 */
VOID WaiDump(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    hex_dump("WaiDump", Elem->Msg, Elem->MsgLen);

    return;
}

/*
    ==========================================================================
    Description:
        This routine function is the timeout handler for certificate
        authentication.

        1.  if retry count > AUTH_WAIT_ACS_REQ_CTR, AE shall re-tramsnit
            auth-activate frame(3). After retry fail 3 times, AE shall disconnect
            this link.
        2.  if retry count > AUTH_WAIT_CERT_RESP_CTR, AE re-transmit
            cert-auth-req frame(6). After retry fail 3 times, AE shall disconnect
            this link.
        3.  if retry count > AUTH_WAIT_ACS_RESP_CTR, ASUE re-transmit
            accsee-auth-req frame(4). After retry fail 3 times, ASUE shall disconnect
            this link.

    ==========================================================================
 */
void WaiCertAuthHSTimerProc(void *eloop_ctx, void *timeout_ctx)
{
    PRTMP_ADAPTER pAd = eloop_ctx;
    PSTA_TABLE_ENTRY pEntry = timeout_ctx;

    if (pEntry && pEntry->Valid)
    {
        pEntry->retry_cnt++;

        // AUTH_WAIT_ACS_RESP_CTR
        if (pEntry->retry_cnt > (AUTH_WAIT_ACS_RESP_CTR + 3))
        {
            // Disconnect this link after ASUE re-transmit access-auth-req frame failure 3 times.
            DBGPRINT(RT_DEBUG_WARN, "Disconnect this link after ASUE re-transmit access-auth-req frame failure 3 times.!!!\n");
            DisconnectStaLink(pAd, pEntry->Aid, REASON_WAI_CERT_AUTH_FAIL);
            return;
        }
        else if (pEntry->retry_cnt > AUTH_WAIT_ACS_RESP_CTR)
        {
            // ASUE re-transmit access-auth-req frame to AE
            DBGPRINT(RT_DEBUG_TRACE, "ASUE re-transmit(%d-time) access-auth-req frame to AE!!!\n", pEntry->retry_cnt - AUTH_WAIT_ACS_RESP_CTR);
            MlmeEnqueue(pAd, WAI_AUTH_STATE_MACHINE, WAI_MLME_ACS_AUTH_REQ, pEntry->Aid, 6, pEntry->Addr);
        }
        // AUTH_WAIT_CERT_RESP_CTR
        else if (pEntry->retry_cnt > (AUTH_WAIT_CERT_RESP_CTR + 3))
        {
            // Disconnect this link after AE re-transmit cert-auth-req frame failure 3 times.
            DBGPRINT(RT_DEBUG_WARN, "Disconnect this link after AE re-transmit cert-auth-req frame failure 3 times.!!!\n");
            DisconnectStaLink(pAd, pEntry->Aid, REASON_WAI_CERT_AUTH_FAIL);
            return;
        }
        else if (pEntry->retry_cnt > AUTH_WAIT_CERT_RESP_CTR)
        {
            // AE re-transmit cert-auth-req frame to AS
            DBGPRINT(RT_DEBUG_TRACE, "AE re-transmit(%d-time) cert-auth-req frame to AS!!!\n", pEntry->retry_cnt - AUTH_WAIT_CERT_RESP_CTR);
            MlmeEnqueue(pAd, WAI_AUTH_STATE_MACHINE, WAI_MLME_CERT_AUTH_REQ, pEntry->Aid, 6, pEntry->Addr);
        }
        // AUTH_WAIT_ACS_REQ_CTR
        else if (pEntry->retry_cnt > (AUTH_WAIT_ACS_REQ_CTR + 3))
        {
            // Disconnet this link after AE re-transmit auth-activate frame failure 3 times.
            DBGPRINT(RT_DEBUG_WARN, "Disconnet this link after AE re-transmit auth-activate frame failure 3 times.!!!\n");
            DisconnectStaLink(pAd, pEntry->Aid, REASON_WAI_CERT_AUTH_FAIL);
            return;
        }
        else if (pEntry->retry_cnt > AUTH_WAIT_ACS_REQ_CTR)
        {
            // AE shall re-tramsnit auth-activate frame(3) to ASUE
            DBGPRINT(RT_DEBUG_TRACE, "AE re-transmit(%d-time) auth-activate frame to ASUE!!!\n", pEntry->retry_cnt - AUTH_WAIT_ACS_REQ_CTR);
            MlmeEnqueue(pAd, WAI_AUTH_STATE_MACHINE, WAI_MLME_AUTH_ACTIVATE, pEntry->Aid, 6, pEntry->Addr);
        }
    }
}


/*
    ==========================================================================
    Description:
        This routine function is the timeout handler for key negotiation
        handshaking.

    ==========================================================================
 */
void WaiKeyHSTimerProc(void *eloop_ctx, void *timeout_ctx)
{
    PRTMP_ADAPTER pAd = eloop_ctx;
    PSTA_TABLE_ENTRY pEntry = timeout_ctx;

    if (pEntry && pEntry->Valid)
    {
        pEntry->retry_cnt++;

        // MCAST_WAIT_RESP_CTR
        if (pEntry->retry_cnt > (MCAST_WAIT_RESP_CTR + 3))
        {
            // De-authentication this link after AE re-transmit response frame failure 3 times.
            DBGPRINT(RT_DEBUG_WARN, "De-authentication this link after AE re-transmit response frame failure 3 times!!!\n");
            DisconnectStaLink(pAd, pEntry->Aid, REASON_WAI_MCAST_HS_TIMEOUT);
            return;
        }
        else if (pEntry->retry_cnt > MCAST_WAIT_RESP_CTR)
        {
            // AE re-transmit notify frame to ASUE
            DBGPRINT(RT_DEBUG_TRACE, "AE re-transmit(%d-time) notify frame to ASUE!!!\n", pEntry->retry_cnt - MCAST_WAIT_RESP_CTR);
            MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_MCAST_KEY_NOTIFY, pEntry->Aid, 6, pEntry->Addr);
        }
        // UCAST_DONE_CTR
        else if (pEntry->retry_cnt > UCAST_DONE_CTR)
        {
            // AE start MCAST key handshake process
            DBGPRINT(RT_DEBUG_TRACE, "AE start MCAST key handshake process!!!\n");
            MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_MCAST_KEY_NOTIFY, pEntry->Aid, 6, pEntry->Addr);
        }
        // UCAST_WAIT_CFM_CTR
        else if (pEntry->retry_cnt > (UCAST_WAIT_CFM_CTR + 3))
        {
            // De-authentication this link after ASUE re-transmit response frame failure 3 times.
            DBGPRINT(RT_DEBUG_WARN, "De-authentication this link after ASUE re-transmit response frame failure 3 times!!!\n");
            DisconnectStaLink(pAd, pEntry->Aid, REASON_WAI_UCAST_HS_TIMEOUT);
            return;
        }
        else if (pEntry->retry_cnt > UCAST_WAIT_CFM_CTR)
        {
            // ASUE re-transmit response frame to AE
            DBGPRINT(RT_DEBUG_TRACE, "ASUE re-transmit(%d-time) response frame to AE!!!\n", pEntry->retry_cnt - UCAST_WAIT_CFM_CTR);
            MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_UCAST_KEY_RESP, pEntry->Aid, 6, pEntry->Addr);
        }
        // UCAST_WAIT_RESP_CTR
        else if (pEntry->retry_cnt > (UCAST_WAIT_RESP_CTR + 3))
        {
            // De-authentication this link after AE re-transmit request frame failure 3 times.
            DBGPRINT(RT_DEBUG_WARN, "De-authentication this link after AE re-transmit request frame failure 3 times.!!!\n");
            DisconnectStaLink(pAd, pEntry->Aid, REASON_WAI_UCAST_HS_TIMEOUT);
            return;
        }
        else if (pEntry->retry_cnt > UCAST_WAIT_RESP_CTR)
        {
            // AE re-transmit request frame to ASUE
            DBGPRINT(RT_DEBUG_TRACE, "AE re-transmit(%d-time) request frame to ASUE!!!\n", pEntry->retry_cnt - UCAST_WAIT_RESP_CTR);
            MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_UCAST_KEY_REQ, pEntry->Aid, 6, pEntry->Addr);
        }
    }
}

VOID WaiGeneratCertBK(
    STA_TABLE_ENTRY     *pEntry,
    UCHAR               *edca_key)
{
    const char          bk_prefix[] = "base key expansion for key and additional nonce";
    UCHAR               temp_key[48];
    const unsigned char *_addr[1];
    UINT32              _len[1];
    UCHAR               cxt[256];
    INT                 cxt_len;

    // Derive BK and its identification
    os_memset(cxt, 0, 256);

    // Concatenate the AE challenge
    os_memcpy(cxt, pEntry->ANONCE, NONCE_LEN);
    cxt_len = NONCE_LEN;

    // Concatenate the ASUE challenge
    os_memcpy(&cxt[cxt_len], pEntry->SNONCE, NONCE_LEN);
    cxt_len += NONCE_LEN;

    // Concatenate the prefix
    os_memcpy(&cxt[cxt_len], bk_prefix, strlen(bk_prefix));
    cxt_len += strlen(bk_prefix);

    kd_hmac_sha256(edca_key,
                   24,
                   cxt,
                   cxt_len,
                   temp_key,
                   48);
    os_memcpy(pEntry->BK, temp_key, 16);

    // Calculate BK authentication flag
    _addr[0] = &temp_key[16];
    _len[0] = 32;
    sha256_vector(1, _addr, _len, pEntry->BK_AUTH_ID);
}

#ifdef OPENSSL_INC
/*
    ==========================================================================
    Description:
        This routine function shall structure the WAI auth-activate frame
        and send it to ASUE.
        It shall be performed in the below condition
        1. AE initiate the certificate authentication process.
        2. If the timeout of auth-activate frame is expired, AE shall send the
           this frame again.

    ==========================================================================
 */
VOID WaiMlmeAuthActivateAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY     *pEntry;
    ULONG               FrameLen = 0;
    PUCHAR              pBuf;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeAuthActivateAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    // Decide the identification flag
    // bit-0 indicate the BK update process.
    // bit-1 indicate the pre-authentication process
    pEntry->id_flag = 0;    // initial value

    // AE trigger the BK update procedure
    if (pEntry->WaiAuthState == WAI_CERT_AUTH_DONE)
    {
        // Set the BK update bit as ON
        pEntry->id_flag |= WAI_FLAG_BK_UPDATE;

        // use the result of the last negotiation
        os_memcpy(pEntry->AUTH_ID, pEntry->BK_AUTH_ID, NONCE_LEN);
    }
    else
    {
        // generate a random number for authenticate identification
        os_get_random(pEntry->AUTH_ID, NONCE_LEN);
    }

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (!pBuf)
        return;

#if 0
    // Construct the outgoing frame
    MakeOutgoingFrame(pBuf,             &FrameLen,
                      1,                &pEntry->id_flag,
                      NONCE_LEN,        pEntry->AUTH_ID,
                      END_OF_ARGS);
#endif

    // Construct the remainder context of the auth-activate frame
    if ((FrameLen = wapi_auth_activate_create(pAd, pEntry->Addr, pBuf)) == 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_auth_activate_create fail !!!\n");
        os_free(pBuf);
        return;
    }

    if (wapi_handle_l2_send(pAd, pEntry, WAI_AUTH_ACTIVATE_MSG, pBuf, FrameLen) == FALSE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "WaiMlmeAuthActivateAction fail \n");
        os_free(pBuf);
        return;
    }

    // Update state
    pEntry->WaiAuthState = WAI_WAIT_ACCESS_AUTH_REQ;

    // Update retry count if this isn't re-transmit procedure
    if (pEntry->retry_cnt == AUTH_CERT_IDLE_CTR)
        pEntry->retry_cnt = AUTH_WAIT_ACS_REQ_CTR;

    // set retry timer
    eloop_register_timeout(1, 0, WaiCertAuthHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiMlmeAuthActivateAction \n");

    return;
}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI access-auth-req frame
        from peer STA(ASUE).
        It shall be performed in the below condition
        1.  After AE sent out auth-activate frame to ASUE, ASUE shall response
            the access-auth-req frame to AE.
        2.  If ASUE wants to trigger the BK update procedure, it would send
            access-auth-req frame to AE.

    ==========================================================================
 */
VOID WaiPeerAccessAuthReqAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    ULONG                   FrameLen = 0;
    PUCHAR                  pBuf;
    PUCHAR                  pMsg;
    UINT32                  MsgLen;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerAccessAuthReqAction \n");

    // check the received length
    if (Elem->MsgLen <= sizeof(HEADER_WAI))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAccessAuthReqAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry || !pEntry->Valid)
        return;

    // Pointer to the WAI unicast key response
    pMsg = &Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    // If AE doesn't sent auth-activate frame.
    if (pEntry->WaiAuthState == WAI_CERT_AUTH_DONE)
    {
        // ASUE trigger BK update procedure through this frame
        DBGPRINT(RT_DEBUG_TRACE, "--> ASUE trigger BK update procedure \n");

        // use the result of the last negotiation
        os_memcpy(pEntry->AUTH_ID, pEntry->BK_AUTH_ID, NONCE_LEN);

        // Check the validity of the authenticate identification
        if (os_memcmp(pMsg + 1, pEntry->AUTH_ID, NONCE_LEN) != 0)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAccessAuthReqAction : the authenticate identification is invalid \n");
            hex_dump("Receive auth-ID", pMsg + 1, NONCE_LEN);
            hex_dump("Desired auth-ID", pEntry->AUTH_ID, NONCE_LEN);
            return;
        }
    }
    else
    {
        // compare the bit-0 and bit-1
        if ((WAI_FLAG_BK_RENEW_IS_ON(*pMsg) != WAI_FLAG_BK_RENEW_IS_ON(pEntry->id_flag)) ||
            (WAI_FLAG_PRE_AUTH_IS_ON(*pMsg) != WAI_FLAG_PRE_AUTH_IS_ON(pEntry->id_flag)))
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAccessAuthReqAction : the flag identification is invalid \n");
            return;
        }
    }

    // record the identification flag of the received frame
    pEntry->id_flag = (*pMsg);

    // sanity check the received access-auth-req frame
    if (wapi_access_auth_request_check(pAd, pEntry->Addr, pMsg, MsgLen) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_check fail !!!\n");
        return;
    }

    // Cancel previous retry timer
    eloop_cancel_timeout(WaiCertAuthHSTimerProc, pAd, pEntry);

    // prepare the field of ADDID (AE_MAC || ASUE_MAC)
    os_memcpy(&pEntry->ADDID[0], pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN); // AE MAC address
    os_memcpy(&pEntry->ADDID[MAC_ADDR_LEN], pEntry->Addr, MAC_ADDR_LEN);            // ASUE MAC address

    // generate a random number for AE Nonce
    os_get_random(pEntry->ANONCE, NONCE_LEN);

    // record the ASUE Nonce of the received frame
    os_memcpy(pEntry->SNONCE, pMsg + 1 + NONCE_LEN, NONCE_LEN);

    //
    // Generate the cert-auth-req frame
    //

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (!pBuf)
        return;

#if 0
    // Construct the cert-auth-req frame
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      12,                               pEntry->ADDID,
                      NONCE_LEN,                        pEntry->ANONCE, // AE nonce
                      NONCE_LEN,                        pEntry->SNONCE, // ASUE nonce
                      END_OF_ARGS);
#endif

    // Construct the remainder of the cert-auth-req frame
    if ((FrameLen = wapi_certificate_auth_request_create(pAd, pEntry->Addr, pBuf)) == 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_certificate_auth_request_create fail !!!\n");
        os_free(pBuf);
        return;
    }

    if (wapi_client_send(pAd, pEntry, WAI_CERT_AUTH_REQ_MSG, pBuf, FrameLen) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "--> wapi_client_send : send fail\n");
        os_free(pBuf);
        return;
    }

    // Update the state
    pEntry->WaiAuthState = WAI_WAIT_CERT_AUTH_RESP;

    // Update retry count and timer
    pEntry->retry_cnt = AUTH_WAIT_CERT_RESP_CTR;
    eloop_register_timeout(1, 0, WaiCertAuthHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerAccessAuthReqAction\n");

    return;

}


/*
    ==========================================================================
    Description:
        This routine function handles to construct the WAI cert-auth-req frame
        and send it to AS.
        It shall be performed in the below condition
        1. If the timeout of cert-auth-req frame is expired, AE shall send the
           this frame again.

    ==========================================================================
 */
VOID WaiMlmeCertAuthReqAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    ULONG                   FrameLen = 0;
    PUCHAR                  pBuf;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeCertAuthReqAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry || !pEntry->Valid)
        return;

    //
    // Generate the cert-auth-req frame
    //
    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (!pBuf)
        return;

#if 0
    // Construct the cert-auth-req frame
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      12,                               pEntry->ADDID,
                      NONCE_LEN,                        pEntry->ANONCE, // AE nonce
                      NONCE_LEN,                        pEntry->SNONCE, // ASUE nonce
                      END_OF_ARGS);
#endif

    // Construct the remainder of the cert-auth-req frame
    if ((FrameLen = wapi_certificate_auth_request_create(pAd, pEntry->Addr, pBuf)) == 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_certificate_auth_request_create fail !!!\n");
        os_free(pBuf);
        return;
    }

    if (wapi_client_send(pAd, pEntry, WAI_CERT_AUTH_REQ_MSG, pBuf, FrameLen) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "--> wapi_client_send : send fail\n");
        os_free(pBuf);
        return;
    }

    // Update the state
    pEntry->WaiAuthState = WAI_WAIT_CERT_AUTH_RESP;

    // Update retry count and timer
    if (pEntry->retry_cnt == AUTH_WAIT_ACS_RESP_CTR)
        pEntry->retry_cnt = AUTH_WAIT_CERT_RESP_CTR;
    eloop_register_timeout(1, 0, WaiCertAuthHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiMlmeCertAuthReqAction\n");

    return;

}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI cert-auth-resp frame
        from AS.
        It shall be performed in the below condition
        1.  After AE sent out cert-auth-resp frame to AS, AS shall response
            the cert-auth-resp frame to AE.

    ==========================================================================
 */
VOID WaiPeerCertAuthRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY     *pEntry;
    ULONG               FrameLen = 0;
    PUCHAR              pBuf;
    PUCHAR              pMsg;
    UINT32              MsgLen;
    UCHAR               temp_ecdk_key[24];
#if 0
    const char          bk_prefix[] = "base key expansion for key and additional nonce";
    UCHAR               temp_key[48];
    const unsigned char *_addr[1];
    UINT32              _len[1];
    UCHAR               cxt[256];
    INT                 cxt_len;
#endif

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerCertAuthRespAction \n");

    // check the received length
    if (Elem->MsgLen <= sizeof(HEADER_WAI))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerCertAuthRespAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry || !pEntry->Valid)
        return;

    // Pointer to the WAI unicast key response
    pMsg = &Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    if (wapi_certificate_auth_response_check(pAd, pEntry->Addr, pMsg, MsgLen, temp_ecdk_key) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_certificate_auth_response_check fail !!!\n");
        return;
    }

    //hex_dump("**temp_ecdk_key", temp_ecdk_key, 24);

    // Cancel previous retry timer
    eloop_cancel_timeout(WaiCertAuthHSTimerProc, pAd, pEntry);

#if 0
    // Derive BK and its identification
    os_memset(cxt, 0, 256);

    // Concatenate the AE challenge
    os_memcpy(cxt, pEntry->ANONCE, NONCE_LEN);
    cxt_len = NONCE_LEN;

    // Concatenate the ASUE challenge
    os_memcpy(&cxt[cxt_len], pEntry->SNONCE, NONCE_LEN);
    cxt_len += NONCE_LEN;

    // Concatenate the prefix
    os_memcpy(&cxt[cxt_len], bk_prefix, strlen(bk_prefix));
    cxt_len += strlen(bk_prefix);

    kd_hmac_sha256(temp_ecdk_key,
                   24,
                   cxt,
                   cxt_len,
                   temp_key,
                   48);
    os_memcpy(pEntry->BK, temp_key, 16);

    // Calculate BK authentication flag
    _addr[0] = &temp_key[16];
    _len[0] = 32;
    sha256_vector(1, _addr, _len, pEntry->BK_AUTH_ID);
#else
    WaiGeneratCertBK(pEntry, temp_ecdk_key);
#endif
    //
    // Generate the cert-auth-req frame
    //

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (!pBuf)
        return;

#if 0
    // Construct the access-auth-resp frame
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      1,                                &pEntry->id_flag,
                      NONCE_LEN,                        pEntry->SNONCE,
                      NONCE_LEN,                        pEntry->ANONCE,
                      1,                                &pEntry->asue_auth_result,
                      END_OF_ARGS);
#endif

    // Construct the remainder of the access-auth-resp frame
    if ((FrameLen = wapi_access_auth_response_create(pAd, pEntry->Addr, pBuf, pMsg, MsgLen))== 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_response_create fail !!!\n");
        os_free(pBuf);
        return;
    }

    if (wapi_handle_l2_send(pAd, pEntry, WAI_ACCESS_AUTH_RESP_MSG, pBuf, FrameLen) == FALSE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "--> wapi_handle_l2_send : send fail\n");
        os_free(pBuf);
        return;
    }

    // Update the state
    pEntry->WaiAuthState = WAI_CERT_AUTH_DONE;

    // Ready to trigger the unicast key negotiation handshaking
    wapi_trigger_sm_timeout(pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerCertAuthRespAction\n");

    return;

}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI auth-activate frame
        from peer STA(AE).
        It shall be performed in the below condition
        1.  Initially, ASUE receive auth-activate frame from AE.
        2.  ASUE receive auth-activate frame form AE for BK-update

    ==========================================================================
 */
VOID WaiPeerAuthActivateAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    ULONG                   FrameLen = 0;
    PUCHAR                  pBuf;
    PUCHAR                  pMsg;
    UINT32                  MsgLen;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerAuthActivateAction \n");

    // check the received length
    if (Elem->MsgLen <= sizeof(HEADER_WAI))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAuthActivateAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry || !pEntry->Valid)
        return;

    // Skip the WAI header
    pMsg = &Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    // Check if this is a BK update procedure
    if (pEntry->WaiAuthState == WAI_CERT_AUTH_DONE &&
        (WAI_FLAG_BK_RENEW_IS_ON(*pMsg)))
    {
        // AE trigger BK update procedure through this frame
        DBGPRINT(RT_DEBUG_TRACE, "--> AE trigger BK update procedure \n");

        // Check the validity of the authenticate identification
        // Need to refer to the result of the last cert-auth negotiation
        if (os_memcmp(pMsg + 1, pEntry->BK_AUTH_ID, NONCE_LEN) != 0)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAuthActivateAction : the authenticate identification is invalid \n");
            hex_dump("Receive auth-ID", pMsg + 1, NONCE_LEN);
            hex_dump("Desired auth-ID", pEntry->BK_AUTH_ID, NONCE_LEN);
            return;
        }
    }

    // sanity check the received auth-activate frame
    if (wapi_auth_activate_check(pAd, pEntry->Addr, pMsg, MsgLen) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_auth_activate_check fail !!!\n");
        return;
    }

    // Cancel previous retry timer
    eloop_cancel_timeout(WaiCertAuthHSTimerProc, pAd, pEntry);

    // record bit-0 & 1 of the identification flag of the received frame
    pEntry->id_flag = (*pMsg) & 0x03;
    // If this is not BK-update procedure, the Bit-2 must ON.
    if (WAI_FLAG_BK_RENEW_IS_ON(pEntry->id_flag) == 0)
        pEntry->id_flag |= WAI_FLAG_CERT_REQ;
    // Todo AlbertY : the bit-3 of the identification flag


    // store the authentication identification from AE
    os_memcpy(pEntry->AUTH_ID, pMsg + 1, NONCE_LEN);

    // generate a random number for ASUE Nonce
    os_get_random(pEntry->SNONCE, NONCE_LEN);
    hex_dump("SNONCE", pEntry->SNONCE, NONCE_LEN);
    //
    // Generate the cert-auth-req frame
    //

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (!pBuf)
        return;

#if 0
    // Construct the cert-auth-req frame
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      1,                                &pEntry->id_flag,
                      NONCE_LEN,                        pEntry->AUTH_ID,    // auth-identification
                      NONCE_LEN,                        pEntry->SNONCE,     // ASUE nonce
                      END_OF_ARGS);
#endif

    // Construct the remainder of the cert-auth-req frame
    if ((FrameLen = wapi_access_auth_request_create(pAd, pEntry->Addr, pBuf)) == 0)
        //if (wapi_access_auth_request_create(pAd, pEntry->Addr, pBuf, &FrameLen) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_create fail !!!\n");
        os_free(pBuf);
        return;
    }

    // send out this frame
    if (wapi_handle_l2_send(pAd, pEntry, WAI_ACCESS_AUTH_REQ_MSG, pBuf, FrameLen) == FALSE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_handle_l2_send fail \n");
        os_free(pBuf);
        return;
    }

    // Update the state
    pEntry->WaiAuthState = WAI_WAIT_ACCESS_AUTH_RESP;

    // Update retry count and timer
    pEntry->retry_cnt = AUTH_WAIT_ACS_RESP_CTR;
    eloop_register_timeout(1, 0, WaiCertAuthHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerAuthActivateAction\n");

    return;

}

/*
    ==========================================================================
    Description:
        This routine function shall structure the WAI access-auth-req frame
        and send it to AE.
        It shall be performed in the below condition
        1. ASUE trigger the BK-update process.
        2. If the timeout of access-auth-req frame is expired, ASUE shall send
           this frame again.

    ==========================================================================
 */
VOID WaiMlmeAccessAuthReqAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY     *pEntry;
    ULONG               FrameLen = 0;
    PUCHAR              pBuf;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeAccessAuthReqAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    pEntry->id_flag = 0;    // initial value

    // ASUE trigger the BK-update procedure
    if (pEntry->WaiAuthState == WAI_CERT_AUTH_DONE)
    {
        // Set the BK update bit as ON
        pEntry->id_flag |= WAI_FLAG_BK_UPDATE;

        // use the result of the last negotiation
        os_memcpy(pEntry->AUTH_ID, pEntry->BK_AUTH_ID, NONCE_LEN);
    }

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (!pBuf)
        return;

#if 0
    // Construct the outgoing frame
    MakeOutgoingFrame(pBuf,             &FrameLen,
                      1,                &pEntry->id_flag,
                      NONCE_LEN,        pEntry->AUTH_ID,
                      NONCE_LEN,        pEntry->SNONCE,
                      END_OF_ARGS);
#endif

    // Construct the remainder context of the access-auth-req frame
    if ((FrameLen = wapi_access_auth_request_create(pAd, pEntry->Addr, pBuf)) == 0)
        //if (wapi_access_auth_request_create(pAd, pEntry->Addr, pBuf, &FrameLen) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_request_create fail !!!\n");
        os_free(pBuf);
        return;
    }

    if (wapi_handle_l2_send(pAd, pEntry, WAI_ACCESS_AUTH_REQ_MSG, pBuf, FrameLen) == FALSE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "WaiMlmeAccessAuthReqAction send fail \n");
        os_free(pBuf);
        return;
    }

    // Update state
    pEntry->WaiAuthState = WAI_WAIT_ACCESS_AUTH_RESP;

    // Update retry count if this isn't re-transmit procedure
    if (pEntry->retry_cnt == AUTH_CERT_IDLE_CTR)
        pEntry->retry_cnt = AUTH_WAIT_ACS_RESP_CTR;

    // set retry timer
    eloop_register_timeout(1, 0, WaiCertAuthHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiMlmeAccessAuthReqAction \n");

    return;
}


/*
    ==========================================================================
    Description:
        This routine function handles the WAI access-auth-resp frame
        from peer STA(AE).
        It shall be performed in the below condition
        1.  When ASUE received access-auth-resp frame from AE, the cert-auth
            handshaking is complete.

    ==========================================================================
 */
VOID WaiPeerAccessAuthRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    PUCHAR                  pMsg;
    UINT32                  MsgLen;
    UCHAR                   temp_ecdk_key[24];

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerAccessAuthRespAction \n");

    // check the received length
    if (Elem->MsgLen <= sizeof(HEADER_WAI))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAccessAuthRespAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry || !pEntry->Valid)
        return;

    // Skip the WAI header
    pMsg = &Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    hex_dump("WAI_ACS_AUTH_RESP", pMsg, 33);

    // Check the bit-0 and bit-1.
    if ((WAI_FLAG_BK_RENEW_IS_ON(*pMsg) != WAI_FLAG_BK_RENEW_IS_ON(pEntry->id_flag)) ||
        (WAI_FLAG_PRE_AUTH_IS_ON(*pMsg) != WAI_FLAG_PRE_AUTH_IS_ON(pEntry->id_flag)))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAccessAuthRespAction : the flag identification is invalid \n");
        printf("%d/%d", *pMsg, pEntry->id_flag);
        return;
    }

    // Check the SNonce field
    if (os_memcmp(pMsg + 1, pEntry->SNONCE, NONCE_LEN) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerAccessAuthRespAction : the SNONCE is invalid \n");
        hex_dump("Receive SNonce", pMsg + 1, NONCE_LEN);
        hex_dump("Desired SNonce", pEntry->SNONCE, NONCE_LEN);
        return;
    }

    // Stort the ANonce
    os_memcpy(pEntry->ANONCE, pMsg + 1 + NONCE_LEN, NONCE_LEN);

    // sanity check the received access-auth-resp frame
    if (wapi_access_auth_response_check(pAd, pEntry->Addr, pMsg, MsgLen, temp_ecdk_key) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_access_auth_response_check fail , MsgLen(%d)!!!\n", MsgLen);
        return;
    }

    // Cancel previous retry timer
    eloop_cancel_timeout(WaiCertAuthHSTimerProc, pAd, pEntry);

    // Generate the BK
    WaiGeneratCertBK(pEntry, temp_ecdk_key);

    // Update the state
    pEntry->WaiAuthState = WAI_CERT_AUTH_DONE;

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerAccessAuthRespAction\n");

    return;

}


#endif // OPENSSL_INC //

/*
    ==========================================================================
    Description:
        This routine function shall structure the WAI unicast key negotiation
        request frame and send it to ASUE.
        It shall be performed in the below condition
        1. AE initiate the unicast key negotiation handshaking.
        2. If the timeout of request frame is expired, AE shall send the
           request frame again.
        3. the unicast rekey

    ==========================================================================
 */
VOID WaiMlmeUcastKeyReqAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY     *pEntry;
    ULONG               FrameLen = 0;
    PUCHAR              pBuf;
    UCHAR               flag = 0;
    UCHAR               usk_id = 0;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeUcastKeyReqAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    // Check if it is an unicast key update procedure
    // if (pEntry->WaiKeyState == WAI_MCAST_KEY_DONE)
    if (pEntry->PortSecured == WAPI_PORT_SECURED)
    {
        // Set the USK update bit as ON
        flag |= WAI_FLAG_USK_UPDATE;

        // Rotate unicast key index 0~1
        usk_id = (pEntry->USKID == 0 ? 1 : 0);

        // use the result of the last negotiation
        os_memcpy(pEntry->ANONCE, pEntry->PTK_SEED, NONCE_LEN);

        DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeUcastKeyReqAction - USK update \n");
    }
    else
    {
        usk_id = pEntry->USKID;

        // generate a random number for AE Nonce
        os_get_random(pEntry->ANONCE, NONCE_LEN);
    }

    // prepare the field of ADDID
    os_memcpy(&pEntry->ADDID[0], pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN); // AE MAC address
    os_memcpy(&pEntry->ADDID[MAC_ADDR_LEN], pEntry->Addr, MAC_ADDR_LEN);            // ASUE MAC address

    // Calculate the BKID
    kd_hmac_sha256(pEntry->BK, 16, pEntry->ADDID, 12, pEntry->BKID, 16);

    //hex_dump("     BKID", pEntry->BKID, 16);

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_KEY_HS_LEN);
    if (!pBuf)
        return;

    // Construct the outgoing frame
    MakeOutgoingFrame(pBuf,             &FrameLen,
                      1,                &flag,
                      16,               pEntry->BKID,
                      1,                &usk_id,
                      12,               pEntry->ADDID,
                      NONCE_LEN,        pEntry->ANONCE,                 // AE challenge
                      END_OF_ARGS);

    //hex_dump("WAI_UNI_KEY_REQ", pBuf, FrameLen);

    if (wapi_handle_l2_send(pAd, pEntry, WAI_UNI_KEY_REQ_MSG, pBuf, FrameLen) == FALSE)
        DBGPRINT(RT_DEBUG_ERROR, "WaiMlmeUcastKeyReqAction error \n");

    // Update state
    pEntry->WaiKeyState = WAI_WAIT_UCAST_RESP;

    // Update retry count
    if (pEntry->retry_cnt == UCAST_IDLE_CTR)
        pEntry->retry_cnt = UCAST_WAIT_RESP_CTR;

    // set retry timer
    eloop_register_timeout(1, 0, WaiKeyHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiMlmeUcastKeyReqAction \n");

    return;
}


/*
    ==========================================================================
    Description:
        This routine function handles the WAI unicast key negotiation request
        frame from peer STA(AE).

    ==========================================================================
 */
VOID WaiPeerUcastKeyReqAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    ULONG                   FrameLen = 0;
    ULONG                   TmpLen = 0;
    PUCHAR                  pBuf;
    UCHAR                   mac[32];    // message authentication code
    PUCAST_KEY_REQ_FRAME    pMsg;
    //WAPI_WIE_STRUCT           wie_info;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerUcastKeyReqAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    // Pointer to the WAI unicast key request
    pMsg = (PUCAST_KEY_REQ_FRAME)&Elem->Msg[sizeof(HEADER_WAI)];

    // Sanity check a peer unicast key request from AE
    // 1.  check the validity of the peer's BKID
    // 1.1 prepare the field of ADDID
    os_memcpy(&pEntry->ADDID[0], pEntry->Addr, MAC_ADDR_LEN);   // AE MAC address
    os_memcpy(&pEntry->ADDID[MAC_ADDR_LEN], pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN);          // ASUE MAC address

    // 1.2 Calculate the BKID
    kd_hmac_sha256(pEntry->BK, 16, pEntry->ADDID, 12, pEntry->BKID, 16);

    // 1.3 Compare the BK
    if (os_memcmp(pEntry->BKID, pMsg->BKID, 16) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerUcastKeyReqAction : the BKID differs with peer one \n");
        return;
    }

    // 2. If the USK update is in progress,
    if (WAI_FLAG_USK_RENEW_IS_ON(pMsg->Flag))
    {
        DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerUcastKeyReqAction - USK update \n");

        // Check the validity of the USKID
        if (pMsg->USKID == pEntry->USKID)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerUcastKeyReqAction : the USKID is invalid \n");
            return;
        }

        // check the validity of AE challenge
        if (os_memcmp(pMsg->AE_CHALLENGE, pEntry->PTK_SEED, NONCE_LEN) != 0)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerUcastKeyReqAction : the AE challenge is invalid \n");
            return;
        }

        // update the USKID
        pEntry->USKID = pMsg->USKID;
    }

    // Cancel the retry timer
    eloop_cancel_timeout(WaiKeyHSTimerProc, pAd, pEntry);

    // 3.  Calculate the unicast key information
    // 3.1 Generate a random number for ASUE challenge and
    //     get AE challenge from AE's request frame
    os_get_random(pEntry->SNONCE, NONCE_LEN);
    os_memcpy(pEntry->ANONCE, pMsg->AE_CHALLENGE, NONCE_LEN);

    // 3.2 Calculate unicast and additional key and
    //     the seed of AE challenge by KD-HMAC-SHA256 algorithm.
    //     Then Generate the seed of AE challenge.
    CalculatePairWiseKey(pEntry);
#if 0
    hex_dump("PTK_SEED", pEntry->PTK_SEED, 32);

    // 3.3 Generate the seed of AE challenge.
    _addr[0] = &pEntry->PTK[64];
    _len[0] = 32;
    sha256_vector(1, _addr, _len, pEntry->PTK_SEED);
#endif

#if 0
    // 3.3 Query the WIE from wireless driver
    os_memset(&wie_info, 0, sizeof(WAPI_WIE_STRUCT));
    wapi_get_wie(pAd, pEntry->apidx, &wie_info);
    pAd->MBSS[pEntry->apidx].WIE_Len = wie_info.wie_len;
    os_memcpy(pAd->MBSS[pEntry->apidx].WIE, wie_info.wie, wie_info.wie_len);
#endif

    // 4.  Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_KEY_HS_LEN);
    if (!pBuf)
        return;

    // 5.  Construct the key negotiation response packet except MIC field
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      1,                                &pMsg->Flag,
                      16,                               pEntry->BKID,
                      1,                                &pEntry->USKID,
                      12,                               pEntry->ADDID,
                      NONCE_LEN,                        pEntry->SNONCE,     // ASUE challenge
                      NONCE_LEN,                        pEntry->ANONCE,     // AE challenge
                      pAd->MBSS[pEntry->apidx].WIE_Len, pAd->MBSS[pEntry->apidx].WIE,
                      END_OF_ARGS);

    // 6.  Use MAK to calculate the MAC(Message authentication code) value
    hmac_sha256(&pEntry->PTK[32], 16, pBuf, FrameLen, mac);

    // Append mic field
    MakeOutgoingFrame(pBuf + FrameLen,                  &TmpLen,
                      LEN_MSG_AUTH_CODE,                mac,
                      END_OF_ARGS);
    FrameLen += TmpLen;

    //hex_dump("WAI_UNI_KEY_RESP", pBuf, FrameLen);

    if (wapi_handle_l2_send(pAd, pEntry, WAI_UNI_KEY_RESP_MSG, pBuf, FrameLen) == FALSE)
    {
        os_free(pBuf);
        DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerUcastKeyReqAction : send fail\n");
        return;
    }

    // Set unicast key to Asic
    wapi_set_ucast_key_proc(pAd, pEntry);

    // Update the state for the unicast key negotiation
    pEntry->WaiKeyState = WAI_WAIT_UCAST_CFM;

    // Update retry count
    pEntry->retry_cnt = UCAST_WAIT_CFM_CTR;

    // set retry timer
    eloop_register_timeout(1, 0, WaiKeyHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerUcastKeyReqAction \n");

    return;
}


/*
    ==========================================================================
    Description:
        This routine function shall structure the WAI unicast key negotiation
        response frame and send it to AE.
        It shall be performed in the below condition
        1. ASUE replies the AE's request frame.
        2. ASUE wants to update the unicast key.
        3. If the timeout of response frame is expired, ASU shall send the
           response frame again.

    ==========================================================================
 */
VOID WaiMlmeUcastKeyRespAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY     *pEntry;
    ULONG               TmpLen = 0;
    ULONG               FrameLen = 0;
    PUCHAR              pBuf;
    UCHAR               flag = 0;
    //UCHAR             usk_id = 0;
    UCHAR               mac[32];    // message authentication code

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeUcastKeyRespAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_KEY_HS_LEN);
    if (!pBuf)
        return;

    // Check if it is an unicast key update procedure
    //if (pEntry->WaiKeyState == WAI_MCAST_KEY_DONE)
    if (pEntry->PortSecured == WAPI_PORT_SECURED)
    {
        // Set the USK update bit as ON
        flag |= WAI_FLAG_USK_UPDATE;

        // rotate unicast key index 0~1
        pEntry->USKID = (pEntry->USKID == 0 ? 1 : 0);
#if 0
        // prepare the field of ADDID
        os_memcpy(&pEntry->ADDID[0], pEntry->Addr, MAC_ADDR_LEN);   // AE MAC address
        os_memcpy(&pEntry->ADDID[MAC_ADDR_LEN], pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN);      // ASUE MAC address

        // Calculate the BKID
        kd_hmac_sha256(pEntry->BK, 16, pEntry->ADDID, 12, pEntry->BKID, 16);
#endif
        // use the result of the last negotiation to get AE challenge
        os_memcpy(pEntry->ANONCE, pEntry->PTK_SEED, NONCE_LEN);
    }

    // generate a random number for ASUE challenge
    os_get_random(pEntry->SNONCE, NONCE_LEN);

    // Construct the key negotiation response packet except MIC field
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      1,                                &flag,
                      16,                               pEntry->BKID,
                      1,                                &pEntry->USKID,
                      12,                               pEntry->ADDID,
                      NONCE_LEN,                        pEntry->SNONCE,     // ASUE challenge
                      NONCE_LEN,                        pEntry->ANONCE,     // AE challenge
                      pAd->MBSS[pEntry->apidx].WIE_Len, pAd->MBSS[pEntry->apidx].WIE,
                      END_OF_ARGS);

    // 6.  Use MAK to calculate the MAC(Message authentication code) value
    hmac_sha256(&pEntry->PTK[32], 16, pBuf, FrameLen, mac);

    // Append mic field
    MakeOutgoingFrame(pBuf + FrameLen,                  &TmpLen,
                      LEN_MSG_AUTH_CODE,                mac,
                      END_OF_ARGS);
    FrameLen += TmpLen;

    //hex_dump("WAI_UNI_KEY_RESP", pBuf, FrameLen);

    if (wapi_handle_l2_send(pAd, pEntry, WAI_UNI_KEY_RESP_MSG, pBuf, FrameLen) == FALSE)
    {
        os_free(pBuf);
        DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerUcastKeyReqAction : send fail\n");
        return;
    }

    // Set unicast key to Asic
    wapi_set_ucast_key_proc(pAd, pEntry);

    // Update the state for the unicast key negotiation
    pEntry->WaiKeyState = WAI_WAIT_UCAST_CFM;

    // Update retry count
    if (pEntry->retry_cnt == UCAST_IDLE_CTR)
        pEntry->retry_cnt = UCAST_WAIT_CFM_CTR;

    // set retry timer
    eloop_register_timeout(1, 0, WaiKeyHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiMlmeUcastKeyRespAction \n");
    return;
}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI unicast key negotiation response
        frame from peer STA(ASUE).

    ==========================================================================
 */
VOID WaiPeerUcastKeyRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    ULONG                   FrameLen = 0;
    ULONG                   TmpLen = 0;
    PUCHAR                  pBuf;
    UCHAR                   tmp_mac[32];
    UCHAR                   rcvd_mac[LEN_MSG_AUTH_CODE];
    PUCAST_KEY_RESP_FRAME   pMsg;
    UINT32                  MsgLen;
    BOOLEAN                 bUskUpdate = FALSE;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerUcastKeyRespAction \n");

    // check the received length
    if (Elem->MsgLen <= (sizeof(HEADER_WAI) + sizeof(UCAST_KEY_RESP_FRAME)))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyRespAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    // Pointer to the WAI unicast key response
    pMsg = (PUCAST_KEY_RESP_FRAME)&Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    // Get the value of MSG_AUTH_CODE field of the received frame
    os_memcpy(rcvd_mac, &Elem->Msg[Elem->MsgLen - LEN_MSG_AUTH_CODE], LEN_MSG_AUTH_CODE);

    // If this is an unicast rekey procedure
    if (WAI_FLAG_USK_RENEW_IS_ON(pMsg->Flag))
    {
        // check the validity of the USKID
        if (pMsg->USKID == pEntry->USKID)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyRespAction : the USKID is invalid \n");
            return;
        }

        // update the USKID
        pEntry->USKID = pMsg->USKID;
        bUskUpdate = TRUE;
    }
    else
    {
        WAPI_WIE_STRUCT wie_info;

        // Query the WIE
        if (wapi_get_wie(pAd, pEntry->apidx, pEntry->Addr, &wie_info) == FALSE)
            return;

        // In infrastruct mode, verify the WIE
        // Compare this value with the WIE field of association request frame
        // If different, disconnect with ASUE.
        if (os_memcmp(pMsg->WIE, wie_info.wie, wie_info.wie_len) != 0)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyRespAction : the WIE doesn't macth\n");
            hex_dump("Receive WIE", pMsg->WIE, wie_info.wie_len);
            hex_dump("Desired WIE", wie_info.wie, wie_info.wie_len);
            return;
        }

        // In Adhoc mode
        // Todo - AlbertY

    }

    // Check the validity of AE challenge
    if (os_memcmp(pMsg->AE_CHALLENGE, pEntry->ANONCE, NONCE_LEN) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyRespAction : the AE challenge is invalid \n");
        hex_dump("Receive AE_C", pMsg->AE_CHALLENGE, 5);
        hex_dump("Desired AE_C", pEntry->ANONCE, 5);
        return;
    }

    // Keep the ASUE challenge from the received message
    os_memcpy(pEntry->SNONCE, pMsg->ASUE_CHALLENGE, NONCE_LEN);

    // Calculate unicast and additional key and
    // the seed of AE challenge by KD-HMAC-SHA256 algorithm
    // Generate the seed of AE challenge
    CalculatePairWiseKey(pEntry);

#if 0
    // Generate the seed of AE challenge
    _addr[0] = &pEntry->PTK[64];
    _len[0] = 32;
    sha256_vector(1, _addr, _len, pEntry->PTK_SEED);
    //sha256_vector(1, &pEntry->PTK[64], 32, pEntry->PTK_SEED);
#endif

    // Verify the value of MSG_AUTH_CODE field
    hmac_sha256(&pEntry->PTK[32], 16, (PUCHAR)pMsg, MsgLen - LEN_MSG_AUTH_CODE, tmp_mac);
    //hmac_sha(&pEntry->PTK[32], 16, &Elem->Msg[sizeof(HEADER_WAI)], MsgLen - sizeof(HEADER_WAI) - LEN_MSG_AUTH_CODE, tmp_mac, LEN_MSG_AUTH_CODE);

    if (os_memcmp(rcvd_mac, tmp_mac, LEN_MSG_AUTH_CODE) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyRespAction : the MSG_AUTH_CODE is different \n");
        hex_dump("Receive mac", rcvd_mac, LEN_MSG_AUTH_CODE);
        hex_dump("Desired mac", tmp_mac, LEN_MSG_AUTH_CODE);
        return;
    }

    // Cancel the retry timer
    eloop_cancel_timeout(WaiKeyHSTimerProc, pAd, pEntry);

    //
    // Generate the key negoiation confirm frame
    //

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_KEY_HS_LEN);
    if (!pBuf)
        return;

    // Construct the key negotiation confirm packet except MIC field
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      1,                                &pMsg->Flag,
                      16,                               pMsg->BKID,
                      1,                                &pMsg->USKID,
                      12,                               pMsg->ADDID,
                      NONCE_LEN,                        pMsg->ASUE_CHALLENGE,   // ASUE challenge
                      pAd->MBSS[pEntry->apidx].WIE_Len, pAd->MBSS[pEntry->apidx].WIE,
                      END_OF_ARGS);

    // Use MAK to calculate the MSG_AUTH_CODE value
    os_memset(tmp_mac, 0, sizeof(tmp_mac));
    hmac_sha256(&pEntry->PTK[32], 16, pBuf, FrameLen, tmp_mac);

    // Append MIC field
    MakeOutgoingFrame(pBuf + FrameLen,                  &TmpLen,
                      LEN_MSG_AUTH_CODE,                tmp_mac,
                      END_OF_ARGS);
    FrameLen += TmpLen;

    if (wapi_handle_l2_send(pAd, pEntry, WAI_UNI_KEY_CONFIRM_MSG, pBuf, FrameLen) == FALSE)
    {
        os_free(pBuf);
        DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerUcastKeyReqAction : send fail\n");
        return;
    }

    // Set unicast key to Asic
    wapi_set_ucast_key_proc(pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    // Update the retry state
    pEntry->retry_cnt = UCAST_DONE_CTR;

    // Update the key state
    pEntry->WaiKeyState = WAI_UCAST_KEY_DONE;

    // If this is an USK update procedure, the M-cast handshaking isn't necessary.
    if (!bUskUpdate)
    {
        // set a timer to trigger M-CAST handshake processing after 1 seconds
        eloop_register_timeout(1, 0, WaiKeyHSTimerProc, pAd, pEntry);
    }

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerUcastKeyRespAction, %s\n", GetWaiKeyStateText(pEntry->WaiKeyState));

    return;
}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI unicast key negotiation confirm
        frame from peer STA(AE).

    ==========================================================================
 */
VOID WaiPeerUcastKeyCfmAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    UCHAR                   tmp_mac[32];
    UCHAR                   rcvd_mac[20];
    PUCAST_KEY_CFM_FRAME    pMsg;
    UINT                    MsgLen;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerUcastKeyCfmAction \n");

    // check the received length
    if (Elem->MsgLen <= (sizeof(HEADER_WAI) + sizeof(UCAST_KEY_CFM_FRAME)))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyCfmAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Pointer to the WAI unicast key confirm
    pMsg = (PUCAST_KEY_CFM_FRAME)&Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    // Get the value of MSG_AUTH_CODE field of the received frame
    os_memcpy(rcvd_mac, &Elem->Msg[Elem->MsgLen - LEN_MSG_AUTH_CODE], LEN_MSG_AUTH_CODE);

    // Check the validity of ASUE challenge field of the received frame
    if (os_memcmp(pMsg->ASUE_CHALLENGE, pEntry->SNONCE, NONCE_LEN) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyCfmAction : the ASUE challenge is invalid \n");
        return;
    }

    // Check the validity of MSG_AUTH_CODE field
    hmac_sha256(&pEntry->PTK[32], 16, (PUCHAR)pMsg, MsgLen - LEN_MSG_AUTH_CODE, tmp_mac);
    if (os_memcmp(rcvd_mac, tmp_mac, LEN_MSG_AUTH_CODE) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyCfmAction : the MSG_AUTH_CODE is different \n");
        hex_dump("Receive mac", rcvd_mac, LEN_MSG_AUTH_CODE);
        hex_dump("Desired mac", tmp_mac, LEN_MSG_AUTH_CODE);
        return;
    }

    // If this isn't an unicast rekey procedure
    if (!WAI_FLAG_USK_RENEW_IS_ON(pMsg->Flag))
    {
        WAPI_WIE_STRUCT wie_info;

        // Query the WIE
        if (wapi_get_wie(pAd, pEntry->apidx, pEntry->Addr, &wie_info) == FALSE)
            return;

        // Verify the WIE. It must be the same as the WIE field of the received
        // beacon and probe-response. If not match, disconnect the link.
        if (os_memcmp(pMsg->WIE, wie_info.wie, wie_info.wie_len) != 0)
        {
            // Drop this frame
            DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerUcastKeyCfmAction : the WIE doesn't macth\n");
            hex_dump("Receive WIE", pMsg->WIE, wie_info.wie_len);
            hex_dump("Desired WIE", wie_info.wie, wie_info.wie_len);
            return;
        }

    }

    // Cancel the retry timer
    eloop_cancel_timeout(WaiKeyHSTimerProc, pAd, pEntry);

    // Update the state of SM
    pEntry->WaiKeyState = WAI_UCAST_KEY_DONE;

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerUcastKeyCfmAction, %s\n", GetWaiKeyStateText(pEntry->WaiKeyState));
    return;
}

/*
    ==========================================================================
    Description:
        This routine function shall structure the WAI multicast key negotiation
        notify frame and send it to ASUE.
        It shall be performed in the below condition
        1. After unicast key handshake completed, AE start multicast key negotiation handshaking.
        2. If the timeout of notify frame is expired, AE shall send the
           request frame again.
        3. the multicast rekey

    ==========================================================================
 */
VOID WaiMlmeMcastKeyNotifyAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY     *pEntry;
    ULONG               FrameLen = 0;
    PUCHAR              pBuf;
    UCHAR               flag = 0;
    ULONG               TmpLen = 0;
    UCHAR               tmp_mac[32];
    //UCHAR             msk_id = 0;
    UCHAR               tx_iv[LEN_TX_IV];
    UCHAR               e_nmk[16];
    UCHAR               e_nmk_len = 16;
    UCHAR               kek[16];
    WAPI_MCAST_KEY_STRUCT   mkey_info;
    INT                 i;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiMlmeMcastKeyNotifyAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    // Check if this entry is valid
    if (!pEntry->Valid)
        return;

    // Todo - STAKey

    // Get the multicast transmit IV through IOCTL
    os_memset(&mkey_info, 0, sizeof(WAPI_MCAST_KEY_STRUCT));
    if (wapi_get_mcast_key_info(pAd, pEntry->apidx, (PUCHAR)&mkey_info) == FALSE)
        return;

    // M-cast key infomation
    pAd->MBSS[pEntry->apidx].MSKID = mkey_info.key_id & 0xFF;

    /* Inverse byte order */
#if 1
    for (i = 0; i < LEN_TX_IV; i++)
    {
        tx_iv[LEN_TX_IV - 1 - i] = mkey_info.m_tx_iv[i] & 0xFF;
    }

    for (i = 0; i < LEN_TX_IV; i++)
    {
        pAd->MBSS[pEntry->apidx].KeyNotifyIv[LEN_TX_IV - 1 - i] = mkey_info.key_announce[i] & 0xFF;
    }
#else
    NdisMoveMemory(tx_iv, mkey_info.m_tx_iv, LEN_TX_IV);
    NdisMoveMemory(pAd->MBSS[pEntry->apidx].KeyNotifyIv, mkey_info.key_announce, LEN_TX_IV);
#endif
    NdisMoveMemory(pAd->MBSS[pEntry->apidx].NMK, mkey_info.NMK, 16);

    // Encrypt NMK
    os_memset(e_nmk, 0, 16);
    os_memcpy(kek, &pEntry->PTK[48], 16);
    wpi_encrypt(pAd->MBSS[pEntry->apidx].KeyNotifyIv,
                pAd->MBSS[pEntry->apidx].NMK,
                16,
                kek,
                e_nmk);

    //printf("--- wpi_encrypt --- \n");
    //hex_dump("ctx", pAd->MBSS[pEntry->apidx].NMK, 16);
    //hex_dump("out", e_nmk, 16);

#if 0
    os_memset(msk, 0, 64);
    // Decrypt the key_data field
    wpi_decrypt(ivp/*pAd->MBSS[pEntry->apidx].KeyNotifyIv*/,
                e_nmk,
                16,
                &pEntry->PTK[48],
                msk);

    printf("--- wpi_decrypt --- \n");
    hex_dump("ivp", pAd->MBSS[pEntry->apidx].KeyNotifyIv, 16);
    hex_dump("ctx", e_nmk, 16);
    hex_dump("kek", &pEntry->PTK[48], 16);
    hex_dump("out", msk, 16);
#endif
    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_KEY_HS_LEN);
    if (!pBuf)
        return;

    /*
           Octet
                +--------------+
             1  |     flag     |
                +--------------+
             1  |    MSKID/    |
                |   STAKeyID   |
                +--------------+
             1  |     USKID    |
                +--------------+
             12 |     ADDID    |
                +--------------+
             16 |     packet   |
                |    sequence  |
                +--------------+
             16 |     key      |
                | notification |
                |      IV      |
                +--------------+
       variable |   key data   |
                +--------------+
             20 |      MAC     |
                +--------------+

     */

    // Construct the outgoing frame
    MakeOutgoingFrame(pBuf,             &FrameLen,
                      1,                &flag,
                      1,                &pAd->MBSS[pEntry->apidx].MSKID,
                      1,                &pEntry->USKID,
                      12,               pEntry->ADDID,
                      LEN_TX_IV,        tx_iv,
                      LEN_TX_IV,        pAd->MBSS[pEntry->apidx].KeyNotifyIv,
                      1,                &e_nmk_len,
                      16,               e_nmk,
                      END_OF_ARGS);

    // Use MAK to calculate the MSG_AUTH_CODE value
    os_memset(tmp_mac, 0, sizeof(tmp_mac));
    hmac_sha256(&pEntry->PTK[32], 16, pBuf, FrameLen, tmp_mac);

    // Append MIC field
    MakeOutgoingFrame(pBuf + FrameLen,                  &TmpLen,
                      LEN_MSG_AUTH_CODE,                tmp_mac,
                      END_OF_ARGS);
    FrameLen += TmpLen;

    if (wapi_handle_l2_send(pAd, pEntry, WAI_MULTI_KEY_NOTIFY_MSG, pBuf, FrameLen) == FALSE)
        DBGPRINT(RT_DEBUG_ERROR, "WaiMlmeMcastKeyNotifyAction error \n");

    // Update retry count
    if (pEntry->WaiKeyState != WAI_WAIT_MCAST_RESP)
        pEntry->retry_cnt = MCAST_WAIT_RESP_CTR;

    // Update state
    pEntry->WaiKeyState = WAI_WAIT_MCAST_RESP;

    // set retry timer
    eloop_register_timeout(1, 0, WaiKeyHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiMlmeMcastKeyNotifyAction \n");

    return;
}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI multicast key negotiation
        response frame.
        AE shall receive the multicast key response packet from ASUE.


    ==========================================================================
 */
VOID WaiPeerMcastKeyRespAction(
    IN PRTMP_ADAPTER    pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    UCHAR                   tmp_mac[32];
    UCHAR                   rcvd_mac[20];
    PMCAST_KEY_RESP_FRAME   pMsg;
    UINT                    MsgLen;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerMcastKeyRespAction \n");

    // check the received length
    if (Elem->MsgLen < (sizeof(HEADER_WAI) + sizeof(MCAST_KEY_RESP_FRAME)))
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyRespAction : the msg length is too short \n");
        return;
    }

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];

    if (!pEntry->Valid)
    {
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyRespAction : this entry is not valid \n");
        return;
    }

    // Pointer to the WAI multicast key response
    pMsg = (PMCAST_KEY_RESP_FRAME)&Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    // Get the value of MSG_AUTH_CODE field of the received frame
    os_memcpy(rcvd_mac, &Elem->Msg[Elem->MsgLen - LEN_MSG_AUTH_CODE], LEN_MSG_AUTH_CODE);

    // Check the validity of MSG_AUTH_CODE field
    hmac_sha256(&pEntry->PTK[32], 16, (PUCHAR)pMsg, MsgLen - LEN_MSG_AUTH_CODE, tmp_mac);
    if (os_memcmp(rcvd_mac, tmp_mac, LEN_MSG_AUTH_CODE) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyRespAction : the MSG_AUTH_CODE is different \n");
        hex_dump("Receive mac", rcvd_mac, LEN_MSG_AUTH_CODE);
        hex_dump("Desired mac", tmp_mac, LEN_MSG_AUTH_CODE);
        return;
    }

    // Todo - verify the flag, STAKeyID

    // Verify MSKID
    if (pMsg->MSKID != pAd->MBSS[pEntry->apidx].MSKID)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyRespAction : the MSKID is mismatch \n");
        return;
    }

    // Verify USKID
    if (pMsg->USKID != pEntry->USKID)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyRespAction : the USKID is mismatch \n");
        return;
    }

    // Verify ADDID field
    if (os_memcmp(pMsg->ADDID, pEntry->ADDID, 12) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyRespAction : the ADDID is not match \n");
        return;
    }

    // Cancel the retry timer
    eloop_cancel_timeout(WaiKeyHSTimerProc, pAd, pEntry);

    // Update the state of SM
    pEntry->WaiKeyState = WAI_MCAST_KEY_DONE;

    // Set the PortSecured state as secured and notify driver
    pEntry->PortSecured = WAPI_PORT_SECURED;
    wapi_set_port_secured_proc(pAd, pEntry);

    // Set group key to driver
    //wapi_set_mcast_key_proc(pAd, pAd->MBSS[pEntry->apidx].GTK, pEntry->apidx);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerMcastKeyRespAction, %s\n", GetWaiKeyStateText(pEntry->WaiKeyState));
    return;
}

/*
    ==========================================================================
    Description:
        This routine function handles the WAI multicast key negotiation notify
        frame from peer STA(AE).

    ==========================================================================
 */
VOID WaiPeerMcastKeyNotifyAction(
    IN PRTMP_ADAPTER pAd,
    IN MLME_QUEUE_ELEM *Elem)
{
    STA_TABLE_ENTRY         *pEntry;
    ULONG                   FrameLen = 0;
    ULONG                   TmpLen = 0;
    PUCHAR                  pBuf;
    UCHAR                   mac[32];    // message authentication code
    UCHAR                   nmk[16];
    UCHAR                   rcvd_mac[LEN_MSG_AUTH_CODE];
    PMCAST_KEY_NOTIFY_FRAME pMsg;
    UINT32                  MsgLen;
    UCHAR                   encode_nmk[16];
    UCHAR                   kek[16];
    UCHAR                   apidx;
    WAPI_MCAST_KEY_STRUCT   mkey_info;

    DBGPRINT(RT_DEBUG_TRACE, "--> WaiPeerMcastKeyNotifyAction \n");

    // Look up entry by wcid
    pEntry = &pAd->StaTab.Content[Elem->Wcid];
    apidx = pEntry->apidx;

    // Pointer to the WAI multicast key notify frame
    pMsg = (PMCAST_KEY_NOTIFY_FRAME)&Elem->Msg[sizeof(HEADER_WAI)];
    MsgLen = Elem->MsgLen - sizeof(HEADER_WAI);

    // Check the validity of flag field
    // Todo by Albert

    // Get the value of MSG_AUTH_CODE field of the received frame
    os_memcpy(rcvd_mac, &Elem->Msg[Elem->MsgLen - LEN_MSG_AUTH_CODE], LEN_MSG_AUTH_CODE);

    // Verify the value of MSG_AUTH_CODE field
    hmac_sha256(&pEntry->PTK[32], 16, (PUCHAR)pMsg, MsgLen - LEN_MSG_AUTH_CODE, mac);
    if (os_memcmp(rcvd_mac, mac, LEN_MSG_AUTH_CODE) != 0)
    {
        // Drop this frame
        DBGPRINT(RT_DEBUG_ERROR, "--> [ERROR] WaiPeerMcastKeyNotifyAction : the MSG_AUTH_CODE is different \n");
        hex_dump("Receive mac", rcvd_mac, LEN_MSG_AUTH_CODE);
        hex_dump("Desired mac", mac, LEN_MSG_AUTH_CODE);
        return;
    }

    // 3. Check key notify IV, it has to be larger than last one.
    //if(os_strncmp((const char *)pMsg->KEY_NOTIFY_IV, (const char *)pAd->MBSS[pEntry->apidx].KeyNotifyIv, LEN_TX_IV) < 0)
    //  return;

    // Update the key notify IV field
    os_memcpy(pAd->MBSS[apidx].KeyNotifyIv, pMsg->KEY_NOTIFY_IV, LEN_TX_IV);

    // Update the MSKID
    pAd->MBSS[apidx].MSKID = pMsg->MSKID;

    os_memcpy(encode_nmk, &pMsg->data[1], 16);
    os_memcpy(kek, &pEntry->PTK[48], 16);
    // Decrypt the key_data field
    wpi_decrypt(pAd->MBSS[apidx].KeyNotifyIv,
                encode_nmk,
                16,
                kek,
                nmk);

    //printf("--- wpi_decrypt --- \n");
    //hex_dump("ctx", encode_nmk, 16);
    //hex_dump("out", nmk, 16);

    os_memcpy(pAd->MBSS[apidx].NMK, nmk, 16);

#if 0
    // Derive the group key information
    kd_hmac_sha256(pAd->MBSS[apidx].NMK,
                   16,
                   (UCHAR *)group_prefix,
                   strlen((const char *)group_prefix),
                   pAd->MBSS[apidx].GTK,
                   32);


    //hex_dump("GTK", pAd->MBSS[pEntry->apidx].GTK, 32);
#endif

    // Allocate a memory for outing frame
    pBuf = os_malloc(MAX_WAI_KEY_HS_LEN);
    if (!pBuf)
        return;

    // Construct the key negotiation response packet except MIC field
    MakeOutgoingFrame(pBuf,                             &FrameLen,
                      1,                                &pMsg->Flag,
                      1,                                &pMsg->MSKID,
                      1,                                &pMsg->USKID,
                      12,                               pMsg->ADDID,
                      LEN_TX_IV,                        pMsg->KEY_NOTIFY_IV,
                      END_OF_ARGS);

    // Use MAK to calculate the MAC(Message authentication code) value
    os_memset(mac, 0, 32);
    hmac_sha256(&pEntry->PTK[32], 16, pBuf, FrameLen, mac);

    // Append mic field
    MakeOutgoingFrame(pBuf + FrameLen,                  &TmpLen,
                      LEN_MSG_AUTH_CODE,                mac,
                      END_OF_ARGS);
    FrameLen += TmpLen;

    //hex_dump("WAI_UNI_KEY_RESP", pBuf, FrameLen);

    if (wapi_handle_l2_send(pAd, pEntry, WAI_MULTI_KEY_RESP_MSG, pBuf, FrameLen) == FALSE)
    {
        os_free(pBuf);
        DBGPRINT(RT_DEBUG_ERROR, "--> WaiPeerMcastKeyNotifyAction : send fail\n");
        return;
    }

    // Set group key info to driver
    NdisZeroMemory(&mkey_info, sizeof(WAPI_MCAST_KEY_STRUCT));
    mkey_info.key_id = pAd->MBSS[apidx].MSKID;
    NdisMoveMemory(mkey_info.m_tx_iv, pMsg->GROUP_TX_IV, LEN_TX_IV);
    NdisMoveMemory(mkey_info.key_announce, pAd->MBSS[apidx].KeyNotifyIv, LEN_TX_IV);
    NdisMoveMemory(mkey_info.NMK, pAd->MBSS[apidx].NMK, 16);
    wapi_set_mcast_key_info(pAd, apidx, (PUCHAR)&mkey_info);

    // Update the state for the key negotiation
    pEntry->WaiKeyState = WAI_MCAST_KEY_DONE;

    // Set the PortSecured state as secured and notify driver
    pEntry->PortSecured = WAPI_PORT_SECURED;
    wapi_set_port_secured_proc(pAd, pEntry);

    // Update retry count
    //pEntry->retry_cnt = UCAST_WAIT_CFM_CTR;

    // set retry timer
    //eloop_register_timeout(1, 0, WaiKeyHSTimerProc, pAd, pEntry);

    // release the memory of the outing frame
    os_free(pBuf);

    DBGPRINT(RT_DEBUG_TRACE, "<-- WaiPeerMcastKeyNotifyAction, %s\n", GetWaiKeyStateText(pEntry->WaiKeyState));
    return;
}

/*
    ==========================================================================
    Description:
        Get WAI frame message type
    Arguments:

    Note:
    ==========================================================================
*/
const char *GetWaiMsgTypeText(CHAR msgType)
{
    if(msgType == WAI_PREAUTH_MSG)
        return "WAI_PREAUTH_MSG";
    if(msgType == WAI_STAKEY_REQ_MSG)
        return "WAI_STAKEY_REQ_MSG";
    if(msgType == WAI_AUTH_ACTIVATE_MSG)
        return "WAI_AUTH_ENABLE_MSG";
    if(msgType == WAI_ACCESS_AUTH_REQ_MSG)
        return "WAI_ACCESS_AUTH_REQ_MSG";
    if(msgType == WAI_ACCESS_AUTH_RESP_MSG)
        return "WAI_ACCESS_AUTH_RESP_MSG";
    if(msgType == WAI_CERT_AUTH_REQ_MSG)
        return "WAI_CERT_AUTH_REQ_MSG";
    if(msgType == WAI_CERT_AUTH_RESP_MSG)
        return "WAI_CERT_AUTH_RESP_MSG";
    if(msgType == WAI_UNI_KEY_REQ_MSG)
        return "WAI_UNI_KEY_REQ_MSG";
    if(msgType == WAI_UNI_KEY_RESP_MSG)
        return "WAI_UNI_KEY_RESP_MSG";
    if(msgType == WAI_UNI_KEY_CONFIRM_MSG)
        return "WAI_UNI_KEY_CONFIRM_MSG";
    if(msgType == WAI_MULTI_KEY_NOTIFY_MSG)
        return "WAI_MULTI_KEY_NOTIFY_MSG";
    if(msgType == WAI_MULTI_KEY_RESP_MSG)
        return "WAI_MULTI_KEY_RESP_MSG";
    else
        return "UNKNOW";
}

/*
    ==========================================================================
    Description:
        Get WAI state text
    Arguments:

    Note:
    ==========================================================================
*/
const char *GetWaiKeyStateText(ULONG state)
{
    if(state == WAI_WAIT_UCAST_RESP)
        return "WAI_WAIT_UCAST_RESP";
    if(state == WAI_WAIT_UCAST_CFM)
        return "WAI_WAIT_UCAST_CFM";
    if(state == WAI_WAIT_MCAST_RESP)
        return "WAI_WAIT_MCAST_RESP";
    if(state == WAI_UCAST_KEY_DONE)
        return "WAI_UCAST_KEY_DONE";
    if(state == WAI_MCAST_KEY_DONE)
        return "WAI_MCAST_KEY_DONE";
    else
        return "IDLE_STATE";
}


/*
    ==========================================================================
    Description:
        This routine function is used to generate the header of WAI.


    ==========================================================================
 */
VOID MakeWaiHeader(
    IN  UCHAR       SubType,
    IN  USHORT      FrameLen,
    IN  USHORT      FrameSeq,
    IN  UCHAR       FragSeq,
    IN  BOOLEAN     bMoreFrag,
    OUT PHEADER_WAI pHdr)
{
    // initialize the WAI header
    os_memset(pHdr, 0, sizeof(HEADER_WAI));

    // Fill in the corresponding parameters
    pHdr->version = htons(WAI_PROTOCOL_VERS);
    pHdr->type = WAI_PROTOCOL_TYPE;
    pHdr->sub_type = SubType;
    pHdr->length = htons(FrameLen + sizeof(HEADER_WAI));
    pHdr->pkt_seq = htons(FrameSeq);
    pHdr->frag_seq = FragSeq;
    pHdr->flag = (bMoreFrag ? BIT(0) : 0);

    return;
}

/*
    ==========================================================================
    Description:
        This routine function is used to calculate the unicast and additional
    key and nonce.

    ==========================================================================
 */
VOID CalculatePairWiseKey(
    IN OUT PSTA_TABLE_ENTRY     pEntry)
{
    UCHAR   cxt[256];
    INT     cxt_len;
    const unsigned char     *_addr[1];
    UINT32                  _len[1];
    const char  prefix[] = "pairwise key expansion for unicast and additional keys and nonce";

    os_memset(cxt, 0, 256);

    // Concatenate the ADDID field
    os_memcpy(cxt, pEntry->ADDID, 12);
    cxt_len = 12;

    // Concatenate the AE challenge
    os_memcpy(&cxt[cxt_len], pEntry->ANONCE, NONCE_LEN);
    cxt_len += NONCE_LEN;

    // Concatenate the ASUE challenge
    os_memcpy(&cxt[cxt_len], pEntry->SNONCE, NONCE_LEN);
    cxt_len += NONCE_LEN;

    // Concatenate the prefix
    os_memcpy(&cxt[cxt_len], prefix, strlen(prefix));
    cxt_len += strlen(prefix);

    // Calculate key
    kd_hmac_sha256(pEntry->BK, 16, cxt, cxt_len, pEntry->PTK, 96);

    //hex_dump("CalculatePairWiseKey", pEntry->PTK, 96);

    _addr[0] = &pEntry->PTK[64];
    _len[0] = 32;
    sha256_vector(1, _addr, _len, pEntry->PTK_SEED);

    return;
}



