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
    Who             When            What
    --------        ----------      ----------------------------------------------
    Albert Yang     2008/4/10       WAPI main routine

*/
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>

//#include <stdlib.h>
//#include <stdio.h>
//#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if.h>           /* for IFNAMSIZ and co... */
#include <linux/wireless.h>
//#include <linux/if_packet.h>
//#include <linux/if_ether.h>

#include "main_def.h"
#include "sms4.h"
#include "wpi_pcrypt.h"
#include "sha256.h"

#ifdef OPENSSL_INC
/*openssl include*/
#include <openssl/err.h>
#include <openssl/evp.h>

#include "pack.h"
#include "debug.h"
#include "proc.h"
#include "x509_cert.h"
#include "cert_auth.h"
#include <stdlib.h>
#endif // OPENSSL_INC //

int    RTDebugLevel = RT_DEBUG_ERROR;

static void usage(void)
{
    DBGPRINT(RT_DEBUG_OFF, "USAGE :  	wapid [optional command]\n");
    DBGPRINT(RT_DEBUG_OFF, "[optional command] : \n");
    DBGPRINT(RT_DEBUG_OFF, "-i <card_number> : indicate which card is used\n");
    DBGPRINT(RT_DEBUG_OFF, "-d <debug_level> : set debug level\n");

    exit(1);
}

static void Handle_usr1(int sig, void *eloop_ctx, void *signal_ctx)
{
#if 0 // marked by AlbertY
    struct hapd_interfaces *rtapds = (struct hapd_interfaces *) eloop_ctx;
    struct rtapd_config *newconf;
    int i;

    DBGPRINT(RT_DEBUG_TRACE,"Reloading configuration\n");
    for (i = 0; i < rtapds->count; i++)
    {
        rtapd *rtapd = rtapds->rtapd[i];
        newconf = Config_read(rtapd->ioctl_sock, rtapd->prefix_wlan_name);
        if (newconf == NULL)
        {
            DBGPRINT(RT_DEBUG_ERROR,"Failed to read new configuration file - continuing with old.\n");
            continue;
        }

        /* TODO: update dynamic data based on changed configuration
         * items (e.g., open/close sockets, remove stations added to
         * deny list, etc.) */
        Radius_client_flush(rtapd);
        Config_free(rtapd->conf);
        rtapd->conf = newconf;
        Apd_free_stas(rtapd);

        /* when reStartAP, no need to reallocate sock
                for (i = 0; i < rtapd->conf->SsidNum; i++)
                {
                    if (rtapd->sock[i] >= 0)
                        close(rtapd->sock[i]);

                    rtapd->sock[i] = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
                    if (rtapd->sock[i] < 0)
                    {
                        perror("socket[PF_PACKET,SOCK_RAW]");
                        return;
                    }
                }*/

        if (Radius_client_init(rtapd))
        {
            DBGPRINT(RT_DEBUG_ERROR,"RADIUS client initialization failed.\n");
            return;
        }
#if MULTIPLE_RADIUS
        for (i = 0; i < rtapd->conf->SsidNum; i++)
            DBGPRINT(RT_DEBUG_TRACE, "auth_serv_sock[%d] = %d\n", i, rtapd->radius->mbss_auth_serv_sock[i]);
#else
        DBGPRINT(RT_DEBUG_TRACE,"rtapd->radius->auth_serv_sock = %d\n",rtapd->radius->auth_serv_sock);
#endif
    }
#endif
}

static void Handle_term(int sig, void *eloop_ctx, void *signal_ctx)
{

    DBGPRINT(RT_DEBUG_ERROR, "Signal %d received - terminating\n", sig);

    eloop_terminate();
}

int RT_ioctl(
    INT     sid,
    INT     param,
    PUCHAR  pData,
    UINT    data_len,
    PUCHAR  pIfName,
    UCHAR   ifNameLen,
    INT     flags)
{
    int             ret = 1;
    struct iwreq    wrq;

    os_memcpy(wrq.ifr_name, pIfName, ifNameLen);
    wrq.ifr_name[ifNameLen] = '\0';

    wrq.u.data.flags = flags;
    wrq.u.data.length = data_len;
    wrq.u.data.pointer = (caddr_t) pData;

    ret = ioctl(sid, param, &wrq);

    return ret;
}

static void wapi_data_cleanup(PRTMP_ADAPTER pAd)
{

    if (pAd->wlan_sock >= 0)
        close(pAd->wlan_sock);
    if (pAd->ioctl_sock >= 0)
        close(pAd->ioctl_sock);
    if (pAd->eth_sock >= 0)
        close(pAd->eth_sock);
    if (pAd->as_udp_sock >= 0)
        close(pAd->as_udp_sock);

    //Radius_client_deinit(rtapd);

    //Config_free(rtapd->conf);
    //rtapd->conf = NULL;

    //free(rtapd->prefix_wlan_name);
}

void wapi_trigger_timer_handler(void *eloop_ctx, void *timeout_ctx)
{
    PRTMP_ADAPTER pAd = eloop_ctx;
    PSTA_TABLE_ENTRY pEntry = timeout_ctx;

    if (pEntry && pEntry->Valid)
    {
        if ((pEntry->AuthMode == WAPI_AUTH_PSK) ||
            ((pEntry->AuthMode == WAPI_AUTH_CERT && pEntry->WaiAuthState == WAI_CERT_AUTH_DONE)))
        {
            pEntry->retry_cnt = UCAST_IDLE_CTR;
            DBGPRINT(RT_DEBUG_TRACE, "Enqueue a trigger msg for WAI-KEY SM!!!\n");
            MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_UCAST_KEY_REQ, pEntry->Aid, 6, pEntry->Addr);
        }
        else if (pEntry->AuthMode == WAPI_AUTH_CERT)
        {
            pEntry->retry_cnt = AUTH_CERT_IDLE_CTR;
            DBGPRINT(RT_DEBUG_TRACE, "Enqueue a trigger msg for WAI-AUTH SM!!!\n");
            MlmeEnqueue(pAd, WAI_AUTH_STATE_MACHINE, WAI_MLME_AUTH_ACTIVATE, pEntry->Aid, 6, pEntry->Addr);
        }

    }
}

void wapi_trigger_sm_timeout(PRTMP_ADAPTER pAd, PSTA_TABLE_ENTRY pEntry)
{
    eloop_cancel_timeout(wapi_trigger_timer_handler, pAd, pEntry);
    eloop_register_timeout(0, 200000, wapi_trigger_timer_handler, pAd, pEntry);
}

BOOLEAN wapi_handle_l2_send(
    PRTMP_ADAPTER       pAd,
    PSTA_TABLE_ENTRY    pEntry,
    UCHAR               MsgType,
    PUCHAR              pMsg,
    INT                 MsgLen)
{
    IEEE_8023_HDR   ieee_8023_hdr;
    HEADER_WAI      wai_hdr;
    //UCHAR         buf[3000];
    PUCHAR          buf_ptr = NULL;
    INT             buf_len = 0;
    PUCHAR          pDataRemaining;
    UINT32          DataRemainingLen;
    UINT32          data_len;
    UINT32          frag_threshold;
    UCHAR           frag_number = 0;


    DBGPRINT(RT_DEBUG_TRACE, "    wapi_handle_l2_send - len(%d), Seq(%d) \n", MsgLen, pEntry->frame_seq);

    // Allocate a memory pool for transmission
    buf_ptr = os_malloc(TX_BUFFER);
    if (buf_ptr == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Can't allocate memory for wapi_handle_l2_send \n");
        return FALSE;
    }

    os_memset(buf_ptr, 0, sizeof(buf_ptr));

    // Create 802.3 header
    os_memcpy(ieee_8023_hdr.DAddr, pEntry->Addr, MAC_ADDR_LEN);
    os_memcpy(ieee_8023_hdr.SAddr, pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN);
    ieee_8023_hdr.ether_type = htons(ETH_P_WAPI);
    os_memcpy(buf_ptr, &ieee_8023_hdr, LEN_HEADER_802_3);
    buf_len = LEN_HEADER_802_3;

    // the fragment threshold
    frag_threshold = pAd->l2_mtu - LEN_HEADER_802_3 - LENGTH_HEADER_WAI;

    // Init the total payload length of this frame.
    pDataRemaining = pMsg;
    DataRemainingLen = MsgLen;

    // Fragment the original outgoing frame
    do
    {
        DBGPRINT(RT_DEBUG_TRACE, "    wapi_handle_l2_send - FragSeq(%d) \n", frag_number);

        // Concatenate WAI header
        if (DataRemainingLen <= frag_threshold)
        {
            // this is the last or only fragment
            // decide the length of the transmitted data
            data_len = DataRemainingLen;
            MakeWaiHeader(MsgType, (USHORT)data_len, pEntry->frame_seq, frag_number, FALSE, &wai_hdr);
            pEntry->frame_seq ++;
        }
        else
        {
            // more fragment is required
            // decide the length of the transmitted data
            data_len = frag_threshold;
            MakeWaiHeader(MsgType, (USHORT)data_len, pEntry->frame_seq, frag_number, TRUE, &wai_hdr);
            frag_number ++;
        }

        // append the WAI header
        buf_len = LEN_HEADER_802_3;
        os_memcpy(buf_ptr + buf_len, &wai_hdr, sizeof(HEADER_WAI));
        buf_len += sizeof(HEADER_WAI);

        // Concatenate the WAI data frame
        os_memcpy(buf_ptr + buf_len, pDataRemaining, data_len);
        buf_len += data_len;

        if (send(pAd->wlan_sock, buf_ptr, buf_len, 0) < 0)
        {
            perror("wapi_handle_l2_send - sendto");
            os_free(buf_ptr);
            return FALSE;
        }

        pDataRemaining += data_len;
        DataRemainingLen -= data_len;

    }
    while(DataRemainingLen > 0);

    // free the memory pool
    os_free(buf_ptr);

    DBGPRINT(RT_DEBUG_TRACE, "    wapi_handle_l2_send (%s)\n", GetWaiMsgTypeText(MsgType));
    return TRUE;
}

static void wapi_handle_l2_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
    PRTMP_ADAPTER pAd = eloop_ctx;
    //unsigned char buf[2500];
    PUCHAR  buf_ptr = NULL;
    UCHAR *Saddr, *Daddr, *pos, *pos_vlan, apidx = 0, isVlanTag = 0;
    USHORT ethertype, i;
    PETHERNET_HEADER    pRxPkt;
    INT  rcvd_len, data_len;
    STA_TABLE_ENTRY  *pEntry = NULL;
    UCHAR RalinkSpecificIe[3] = {0x00, 0x0c, 0x43};
    //UCHAR ralink_wapi_hdr_len = 7;

    buf_ptr = os_malloc(RX_BUFFER);
    if (buf_ptr == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Can't allocate memory for wapi_handle_l2_receive \n");
        return;
    }

    rcvd_len = recv(sock, buf_ptr, RX_BUFFER, 0);
    if (rcvd_len < 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_handle_l2_receive can't receive valid packet.\n");
        goto out;
    }

    //hex_dump("wapi_handle_l2_receive", buf, rcvd_len);

    // Pointer to the received packet
    pRxPkt = (PETHERNET_HEADER)buf_ptr;
    data_len = rcvd_len - LEN_HEADER_802_3;
    if (data_len < LENGTH_HEADER_WAI)
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_handle_l2_receive : it is too short (%d)\n", rcvd_len);
        goto out;
    }

    Saddr = pRxPkt->Saddr;
    Daddr = pRxPkt->Daddr;
    ethertype = pRxPkt->Ethtype[0] << 8;
    ethertype |= pRxPkt->Ethtype[1];

#ifdef ETH_P_VLAN
    if (ethertype == ETH_P_VLAN)
    {
        pos_vlan = pRxPkt->RcvdData;

        if (data_len >= 4)
        {
            ethertype = *(pos_vlan+2) << 8;
            ethertype |= *(pos_vlan+3);
        }

        if (ethertype == ETH_P_WAPI)
        {
            isVlanTag = 1;
            DBGPRINT(RT_DEBUG_TRACE, "Recv vlan tag for WAPI. (%02x %02x)\n", *(pos_vlan), *(pos_vlan+1));
        }
    }
#endif

    if (ethertype == ETH_P_WAPI)
    {
        // search this packet is coming from which interface
        for (i = 0; i < pAd->mbss_num; i++)
        {
            if (os_memcmp(Daddr, pAd->MBSS[i].wlan_addr, MAC_ADDR_LEN) == 0)
            {
                apidx = i;
                break;
            }
        }

        if(i >= pAd->mbss_num)
        {
            DBGPRINT(RT_DEBUG_WARN, "sock not found (sock=%d)!!!\n", sock);
            goto out;;
        }


        DBGPRINT(RT_DEBUG_TRACE, "Receive WAI packet from ra%d\n", apidx);

    }
    else
    {
        DBGPRINT(RT_DEBUG_ERROR, "Receive unexpected ethertype 0x%04X!!!\n", ethertype);
        goto out;
    }

    // Pointer to payload
    pos = pRxPkt->RcvdData;

    // Skip vlan tag(4-bytes)
    if (isVlanTag)
    {
        pos += 4;
        data_len -= 4;
    }

    // Look up the STA info
    pEntry = StaTableLookup(pAd, Saddr);

    // If the STA doesn't exist, insert it to table
    if (pEntry == NULL)
        pEntry = StaTableInsertEntry(pAd, Saddr, apidx);

    if (pEntry)
    {
        // Check if this is a proprietary frame
        if (os_memcmp(pos, RalinkSpecificIe, 3) == 0)
        {
            switch (*(pos+3))
            {
                case WAI_MLME_CERT_AUTH_START:
                    DBGPRINT(RT_DEBUG_TRACE, "Receive a trigger msg for WAI-AUTH SM!!!\n");
                    pEntry->retry_cnt = AUTH_CERT_IDLE_CTR;
                    wapi_trigger_sm_timeout(pAd, pEntry);
                    break;

                case WAI_MLME_KEY_HS_START:
                    DBGPRINT(RT_DEBUG_TRACE, "Receive a trigger msg for WAI-KEY SM!!!\n");
                    pEntry->retry_cnt = UCAST_IDLE_CTR;
                    wapi_trigger_sm_timeout(pAd, pEntry);
                    break;

                case WAI_MLME_UPDATE_BK:
                    DBGPRINT(RT_DEBUG_TRACE, "Receive a trigger msg to update BK!!!\n");
                    // todo - AlbertY
                    break;

                case WAI_MLME_UPDATE_USK:
                    DBGPRINT(RT_DEBUG_TRACE, "\nReceive a trigger msg to update USK!!!\n");

                    if (pEntry->PortSecured != WAPI_PORT_SECURED)
                        break;

                    pEntry->retry_cnt = UCAST_IDLE_CTR;
                    if (os_memcmp(pEntry->ADDID, pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN) == 0)
                        MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_UCAST_KEY_REQ, pEntry->Aid, 6, pEntry->Addr);
                    else
                        MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_UCAST_KEY_RESP, pEntry->Aid, 6, pEntry->Addr);
                    break;

                case WAI_MLME_UPDATE_MSK:
                    DBGPRINT(RT_DEBUG_TRACE, "\nReceive a trigger msg to update MSK!!\n");

                    if (pEntry->PortSecured != WAPI_PORT_SECURED)
                        break;

                    pEntry->retry_cnt = UCAST_DONE_CTR;
                    if (os_memcmp(pEntry->ADDID, pAd->MBSS[pEntry->apidx].wlan_addr, MAC_ADDR_LEN) == 0)
                        MlmeEnqueue(pAd, WAI_KEY_STATE_MACHINE, WAI_MLME_MCAST_KEY_NOTIFY, pEntry->Aid, 6, pEntry->Addr);
                    break;

                case 0xff:
                    DBGPRINT(RT_DEBUG_TRACE, "Receive a trigger cmd to delete this entry !!!\n");
                    StaTableDeleteEntry(pAd, pEntry->Aid, pEntry->Addr);
                    break;

                default:
                    DBGPRINT(RT_DEBUG_WARN, "Receive unexpected ralink type(%d)!!!\n", *(pos+3));
                    break;
            }

#if 0
            // check if the WIE is appended.
            if ((data_len > ralink_wapi_hdr_len + 2) &&
                (*(pos + ralink_wapi_hdr_len) == 0x44))
            {
                // Record this WIE
                pEntry->WIE_Len = data_len - ralink_wapi_hdr_len;
                os_memcpy(pEntry->WIE, pos + ralink_wapi_hdr_len, pEntry->WIE_Len);

                hex_dump("WIE", pEntry->WIE, pEntry->WIE_Len);
            }
#endif
        }
        else
        {
            PHEADER_WAI pWaiHdr = (PHEADER_WAI)pos;

            // Re-assemble the fragmented WAI frame
            if (!(pWaiHdr->frag_seq == 0 && pWaiHdr->flag == 0))
            {
                DBGPRINT(RT_DEBUG_TRACE, "Receive a fragment packet(seq-%d), len(%d/%d)\n", pWaiHdr->frag_seq, ntohs(pWaiHdr->length), data_len);

                // The first fragmented packet
                if (pWaiHdr->frag_seq == 0)
                {
                    // Record the received frame
                    os_memcpy(pAd->FragFrame, pos, data_len);
                    pAd->TotalFragLen = data_len;
                    goto out;
                }
                // The middle and last fragmented packet
                else
                {
                    PHEADER_WAI pDesiredHdr = (PHEADER_WAI)pAd->FragFrame;

                    // Check its packet sequence
                    if (pDesiredHdr->pkt_seq != pWaiHdr->pkt_seq)
                    {
                        DBGPRINT(RT_DEBUG_ERROR, "The packet sequence number doesn't match !!!\n");
                        goto out;
                    }

                    // Check its fragment sequence
                    if (pDesiredHdr->frag_seq + 1 != pWaiHdr->frag_seq)
                    {
                        DBGPRINT(RT_DEBUG_ERROR, "The fragment sequence number doesn't match !!!\n");
                        goto out;
                    }

                    // replace the WAI header
                    os_memcpy(pAd->FragFrame, pos, LENGTH_HEADER_WAI);

                    // Append this fragmented packet
                    os_memcpy(pAd->FragFrame + pAd->TotalFragLen,
                              pos + LENGTH_HEADER_WAI,
                              data_len - LENGTH_HEADER_WAI);

                    // Update the total length
                    pAd->TotalFragLen += (data_len - LENGTH_HEADER_WAI);

                    // This is the last packet
                    if (pWaiHdr->flag == 0)
                    {
                        pos = pAd->FragFrame;
                        data_len = pAd->TotalFragLen;
                        DBGPRINT(RT_DEBUG_TRACE, "Receive a total fragment len(%d)\n", data_len);
                    }
                    else
                        goto out;
                }

            }

            // Dispatch the received frame to mlme queue
            if (pos)
            {
                MlmeEnqueueForRecv(pAd, pEntry->Aid, data_len, pos);
            }
        }

    }

out:
    os_free(buf_ptr);
    return;

}

SHORT wapi_client_send(
    PRTMP_ADAPTER       pAd,
    PSTA_TABLE_ENTRY    pEntry,
    UCHAR               MsgType,
    PUCHAR              pMsg,
    INT                 MsgLen)
{
    HEADER_WAI      wai_hdr;
    UCHAR           buf[3000];
    INT             buf_len = 0;

    DBGPRINT(RT_DEBUG_TRACE, "    wapi_client_send - Seq(%d) \n", pEntry->frame_seq);

    os_memset(buf, 0, sizeof(buf));

    // Fragment the original outgoing frame
    // Todo - AlbertY

    // Concatenate WAI header
    // The frame sequence of WAI header is always be 1.
    MakeWaiHeader(MsgType, (USHORT)MsgLen, 1/*pEntry->frame_seq*/, 0, FALSE, &wai_hdr);
    //pEntry->frame_seq ++;

    os_memcpy(buf, &wai_hdr, sizeof(HEADER_WAI));
    buf_len += sizeof(HEADER_WAI);

    // Concatenate the WAI data frame
    os_memcpy(&buf[buf_len], pMsg, MsgLen);
    buf_len += MsgLen;

    if (send(pAd->as_udp_sock, buf, buf_len, 0) < 0)
    {
        perror("send[AS]");
        return -1;
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_client_send\n");

    return 0;
}

static void wapi_client_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
    PRTMP_ADAPTER pAd = eloop_ctx;
    unsigned char recv_buf[2500];
    INT  recv_len;
    PSTA_TABLE_ENTRY  pEntry = NULL;
    //UCHAR temp_ecdk_key[24] = {0};

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_client_receive\n");

    recv_len = recv(sock, recv_buf, sizeof(recv_buf), 0);
    if (recv_len < 0)
    {
        perror("recv[AS]");
        return;
    }

    if (recv_len == sizeof(recv_buf))
    {
        DBGPRINT(RT_DEBUG_ERROR,"Possibly too long UDP frame for our buffer - dropping it\n");
        return;
    }

    if (recv_len < (LENGTH_HEADER_WAI + (2 * MAC_ADDR_LEN)))
    {
        DBGPRINT(RT_DEBUG_ERROR, "wapi_client_receiveit - the length is too short (%d)\n", recv_len);
        return;
    }

    // Look up the STA info
    pEntry = StaTableLookup(pAd, &recv_buf[LENGTH_HEADER_WAI + MAC_ADDR_LEN]);

    if (pEntry && pEntry->Valid)
    {
        PHEADER_WAI pWaiHdr = (PHEADER_WAI)recv_buf;

        // Defragment the WAI frame
        if ((pWaiHdr->flag & 0x01) == 0x01)
        {
            // Todo - AlbertY
        }
        else
        {
            // This is only one or last fragment frame
            // Dispatch the received frame to mlme queue
            // Todo - AlbertY
            MlmeEnqueueForRecv(pAd, pEntry->Aid, recv_len, recv_buf);
        }
    }

#if 0
    if (wapi_certificate_auth_response_check(pAd, asue_addr, recv_buf, recv_len, temp_ecdk_key) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_certificate_auth_response_check fail !!!\n");
        return;
    }
#endif

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_client_receive\n");

}

VOID wapi_set_ucast_key_proc(
    PRTMP_ADAPTER       pAd,
    PSTA_TABLE_ENTRY    pEntry)
{
    WAPI_UCAST_KEY_STRUCT ukey_info;

    // zero this structure
    os_memset(&ukey_info, 0, sizeof(WAPI_UCAST_KEY_STRUCT));

    // fill in the related information
    os_memcpy(ukey_info.Addr, pEntry->Addr, MAC_ADDR_LEN);
    ukey_info.key_id = pEntry->USKID;
    os_memcpy(ukey_info.PTK, pEntry->PTK, 64);

    if (RT_ioctl(pAd->ioctl_sock,
                 RT_PRIV_IOCTL,
                 (PUCHAR)&ukey_info,
                 sizeof(WAPI_UCAST_KEY_STRUCT),
                 pAd->MBSS[pEntry->apidx].ifname,
                 pAd->MBSS[pEntry->apidx].ifname_len,
                 RT_OID_802_11_UCAST_KEY_INFO) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," wapi_set_ucast_key_proc - ioctl failure (%s)\n", pAd->MBSS[pEntry->apidx].ifname);
        return;
    }
}


VOID wapi_set_mcast_key_info(
    PRTMP_ADAPTER       pAd,
    UCHAR               apidx,
    PUCHAR              mkey_info_ptr)
{
    if (RT_ioctl(pAd->ioctl_sock,
                 RT_PRIV_IOCTL,
                 mkey_info_ptr,
                 sizeof(WAPI_MCAST_KEY_STRUCT),
                 pAd->MBSS[apidx].ifname,
                 pAd->MBSS[apidx].ifname_len,
                 RT_OID_802_11_MCAST_KEY_INFO) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," wapi_set_mcast_key_info - ioctl failure (%s)\n", pAd->MBSS[apidx].ifname);
        return;
    }
}

VOID wapi_set_port_secured_proc(
    PRTMP_ADAPTER       pAd,
    PSTA_TABLE_ENTRY    pEntry)
{
    WAPI_PORT_SECURE_STRUCT PortMsg;

    //DBGPRINT(RT_DEBUG_OFF, "==>ioctl_sock(%d)\n", pAd->ioctl_sock);

    os_memset(&PortMsg, 0, sizeof(WAPI_PORT_SECURE_STRUCT));
    os_memcpy(PortMsg.Addr, pEntry->Addr, MAC_ADDR_LEN);
    PortMsg.state = (USHORT)pEntry->PortSecured;

    if (RT_ioctl(pAd->ioctl_sock,
                 RT_PRIV_IOCTL,
                 (PUCHAR)&PortMsg,
                 sizeof(WAPI_PORT_SECURE_STRUCT),
                 pAd->MBSS[pEntry->apidx].ifname,
                 pAd->MBSS[pEntry->apidx].ifname_len,
                 RT_OID_802_11_PORT_SECURE_STATE) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," wapi_set_port_secured_proc - ioctl failure (%s)\n", pAd->MBSS[pEntry->apidx].ifname);
        return;
    }
}

BOOLEAN wapi_get_mcast_tx_iv(
    IN  PRTMP_ADAPTER       pAd,
    IN  UCHAR               apidx,
    OUT PUCHAR              pTxIv)
{
    if (RT_ioctl(pAd->ioctl_sock,
                 RT_PRIV_IOCTL,
                 pTxIv,
                 LEN_TX_IV,
                 pAd->MBSS[apidx].ifname,
                 pAd->MBSS[apidx].ifname_len,
                 OID_802_11_MCAST_TXIV) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," wapi_get_mcast_tx_iv - ioctl failure (%s)\n", pAd->MBSS[apidx].ifname);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN wapi_get_wie(
    IN  PRTMP_ADAPTER       pAd,
    IN  UCHAR               apidx,
    IN  PUCHAR              pAddr,
    OUT PWAPI_WIE_STRUCT    wie_ptr)
{
    os_memset(wie_ptr, 0, sizeof(WAPI_WIE_STRUCT));
    os_memcpy(wie_ptr->addr, pAddr, MAC_ADDR_LEN);

    if (RT_ioctl(pAd->ioctl_sock,
                 RT_PRIV_IOCTL,
                 (PUCHAR)wie_ptr,
                 sizeof(WAPI_WIE_STRUCT),
                 pAd->MBSS[apidx].ifname,
                 pAd->MBSS[apidx].ifname_len,
                 OID_802_11_WAPI_IE) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," IF(%s) wapi_get_wie - ioctl failure. \n", pAd->MBSS[apidx].ifname);
        return FALSE;
    }

    if (wie_ptr->wie_len == 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," IF(%s) wapi_get_wie - the WIE is empty. \n", pAd->MBSS[apidx].ifname);
        return FALSE;
    }

    return TRUE;
}


BOOLEAN wapi_get_mcast_key_info(
    IN  PRTMP_ADAPTER       pAd,
    IN  UCHAR               apidx,
    OUT PUCHAR              mkey_info_ptr)
{
    if (RT_ioctl(pAd->ioctl_sock,
                 RT_PRIV_IOCTL,
                 mkey_info_ptr,
                 sizeof(WAPI_MCAST_KEY_STRUCT),
                 pAd->MBSS[apidx].ifname,
                 pAd->MBSS[apidx].ifname_len,
                 OID_802_11_MCAST_KEY_INFO) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR," wapi_get_mcast_key_info - ioctl failure (%s)\n", pAd->MBSS[apidx].ifname);
        return FALSE;
    }

    return TRUE;
}


VOID DisconnectStaLink(
    IN PRTMP_ADAPTER    pAd,
    IN INT              wcid,
    IN USHORT           reason)
{
    PSTA_TABLE_ENTRY pEntry;

    pEntry = &pAd->StaTab.Content[wcid];

    if (pEntry && pEntry->Valid)
    {
        MLME_DEAUTH_REQ_STRUCT DeauthInfo;

        os_memcpy(DeauthInfo.Addr, pEntry->Addr, MAC_ADDR_LEN);
        DeauthInfo.Reason = reason;

        if (RT_ioctl(pAd->ioctl_sock,
                     RT_PRIV_IOCTL,
                     (PUCHAR)&DeauthInfo,
                     sizeof(MLME_DEAUTH_REQ_STRUCT),
                     pAd->MBSS[pEntry->apidx].ifname,
                     pAd->MBSS[pEntry->apidx].ifname_len,
                     RT_OID_802_11_DEAUTHENTICATION) != 0)
        {
            DBGPRINT(RT_DEBUG_ERROR," DisConnectLink - ioctl failure (%s)\n", pAd->MBSS[pEntry->apidx].ifname);
            return;
        }

        // Delete this entry
        // StaTableDeleteEntry(pAd, pEntry->Aid, pEntry->Addr);

    }

}

static BOOLEAN wapi_init_sockets(PRTMP_ADAPTER pAd)
{
    struct ifreq ifr;
    struct sockaddr_ll addr;
    INT i;


    // 1. Initiate wireless interface socket for WAI protocol
    pAd->wlan_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_WAPI));

    if (pAd->wlan_sock < 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Could not create a socket for WAI\n");
        return FALSE;
    }

    if (eloop_register_read_sock(pAd->wlan_sock, wapi_handle_l2_receive, pAd, NULL))
    {
        DBGPRINT(RT_DEBUG_ERROR, "Could not register read socket\n");
        return FALSE;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, (const char *)pAd->wapi_ifname);
    DBGPRINT(RT_DEBUG_TRACE, "Register WAI interface as (%s)\n", ifr.ifr_name);

    if (ioctl(pAd->wlan_sock, SIOCGIFINDEX, &ifr) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Fail : ioctl(SIOCGIFINDEX)\n");
        return FALSE;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(pAd->wlan_sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Fail : bind\n");
        return FALSE;
    }

    /* get the dev_name MACADDR */
    if (ioctl(pAd->wlan_sock, SIOCGIFMTU, &ifr) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Fail - ioctl(SIOCGIFMTU)]\n");
        return FALSE;
    }
    pAd->l2_mtu = ifr.ifr_mtu;

    if (ioctl(pAd->wlan_sock, SIOCGIFHWADDR, &ifr) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Fail - ioctl(SIOCGIFHWADDR)]\n");
        return FALSE;
    }
    os_memcpy(pAd->l2_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    DBGPRINT(RT_DEBUG_TRACE, "Opening WAI raw packet socket (socknum=%d,ifindex=%d)\n", pAd->wlan_sock, addr.sll_ifindex);
    DBGPRINT(RT_DEBUG_TRACE, "IF-%s MAC Address = " MACSTR ", mtu=%d \n", ifr.ifr_name, MAC2STR(pAd->l2_addr), pAd->l2_mtu);

    // 2. Get wireless interface MAC address
    for (i = 0; i < pAd->mbss_num; i++)
    {
        INT s = -1;

        s = socket(AF_INET, SOCK_DGRAM, 0);

        if (s < 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "Fail - socket[AF_INET,SOCK_DGRAM]\n");
            return FALSE;
        }

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, (const char *)pAd->MBSS[i].ifname, pAd->MBSS[i].ifname_len);

        // Get MAC address
        if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0)
        {
            DBGPRINT(RT_DEBUG_ERROR, "Fail - ioctl(SIOCGIFHWADDR)]\n");
            close(s);
            return FALSE;
        }

        DBGPRINT(RT_DEBUG_TRACE, " Device %s has ifr.ifr_hwaddr.sa_family %d\n",ifr.ifr_name, ifr.ifr_hwaddr.sa_family);
        if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        {
            DBGPRINT(RT_DEBUG_ERROR, " IF-%s : Invalid HW-addr family 0x%04x\n", ifr.ifr_name, ifr.ifr_hwaddr.sa_family);
            close(s);
            return FALSE;
        }

        os_memcpy(pAd->MBSS[i].wlan_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        DBGPRINT(RT_DEBUG_TRACE, "IF-%s MAC Address = " MACSTR "\n", ifr.ifr_name, MAC2STR(pAd->MBSS[i].wlan_addr));

        close(s);
    }


    return TRUE;
}

#define AS_PORT 3810
#define AS_SERVER_IP "192.168.222.174"

static BOOLEAN wapi_init_as_udp_socket(PRTMP_ADAPTER pAd)
{
    struct sockaddr_in serv;

    if (pAd->cert_info.config.used_cert == 0)
        return TRUE;

    DBGPRINT(RT_DEBUG_TRACE, "======> wapi_init_as_udp_socket\n");

    pAd->as_udp_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (pAd->as_udp_sock < 0)
    {
        perror("socket[PF_INET,SOCK_DGRAM]");
        return FALSE;
    }

#if 0
    pAd->auth_server.as_port = AS_PORT;
    inet_aton(AS_SERVER_IP, &pAd->auth_server.as_addr);
#endif

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = pAd->auth_server.as_addr.s_addr;
    serv.sin_port = htons(pAd->auth_server.as_port);

    if(connect(pAd->as_udp_sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
    {
        perror("connect[as server]");
        return FALSE;
    }

    if (eloop_register_read_sock(pAd->as_udp_sock, wapi_client_receive, pAd, NULL))
    {
        DBGPRINT(RT_DEBUG_ERROR,"Could not register read socket for authentication server\n");
        return FALSE;
    }

    DBGPRINT(RT_DEBUG_TRACE, "<====== wapi_init_as_udp_socket\n");

    return TRUE;
}

static BOOLEAN wapi_setup_interface(PRTMP_ADAPTER pAd)
{
    //INT       i;

    if (wapi_init_sockets(pAd) == FALSE)
        return FALSE;

    if (wapi_init_as_udp_socket(pAd) == FALSE)
        return FALSE;

    return TRUE;
}

static BOOLEAN wapi_data_init(PRTMP_ADAPTER pAd, const char *ifname, INT    ifname_len)
{

    os_memset(pAd, 0, sizeof(RTMP_ADAPTER));

    // Allocate a memory pool for defragment procedure
    pAd->FragFrame = os_malloc(MAX_WAI_AUTH_HS_LEN);
    if (pAd->FragFrame == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "malloc pAd->FragFrame failed\n");
        return FALSE;
    }

    // Initiate ioctl socket
    pAd->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (pAd->ioctl_sock < 0)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Could not initiate ioctl socket \n");
        return FALSE;
    }

    // Initialize configuration
    if (config_read(pAd, (PUCHAR)ifname, ifname_len) == FALSE)
    {
        DBGPRINT(RT_DEBUG_ERROR, "Could not read WAPI configuration \n");
        return FALSE;
    }

    pAd->wlan_sock = -1;
    pAd->eth_sock = -1;

    return TRUE;

}

#ifdef OPENSSL_INC
static BOOLEAN wapi_certificate_init(PRTMP_ADAPTER pAd)
{
    if(pAd->cert_info.config.used_cert > 0)
    {
        INT idx;

        /* init openssl */
        CRYPTO_malloc_debug_init();
        CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
        ERR_load_crypto_strings();
        OpenSSL_add_all_digests();

        // init X509
        X509_init();

        if (wapi_register_certificate(pAd) != 0)
            return FALSE;

        ap_initialize_signature_alg(pAd);

        wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->user_cert_st,
                                &(pAd->local_user_id),
                                pAd->cert_info.config.used_cert);
        printf("local user id\n");
        DPrint_string(pAd->local_user_id.id_data, pAd->local_user_id.id_len);

#if 0
        wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->asu_cert_st,
                                &(pAd->asu_id),
                                pAd->cert_info.config.used_cert);
        printf("asu id\n");
        DPrint_string(pAd->asu_id.id_data, pAd->asu_id.id_len);
#endif
        for(idx=0; idx<pAd->cert_info.config.as_no; idx++)
        {
            wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->asu_cert_st[idx],
                                    &(pAd->asu_id[idx]),
                                    pAd->cert_info.config.used_cert)!=0;
            printf("asu id (%d)\n", idx+1);
            DPrint_string(pAd->asu_id[idx].id_data, pAd->asu_id[idx].id_len);
        }

        if (pAd->cert_info.config.cert_mode == THREE_CERTIFICATE_MODE)
        {
            wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->ca_cert_st,
                                    &(pAd->ca_id),
                                    pAd->cert_info.config.used_cert);
            printf("ca id\n");
            DPrint_string(pAd->ca_id.id_data, pAd->ca_id.id_len);
        }

        wai_initialize_ecdh(&pAd->local_ecdh);
    }

    return TRUE;

}
#endif // OPENSSL_INC //

VOID ProcessSha()
{
    //UCHAR key1[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    //                0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    //                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};
    // hmac_sha test parameter
    UCHAR key4[4] = {0x4a, 0x65, 0x66, 0x65};
    UCHAR out_data_4[32];
    //UCHAR out_data_4_1[32];
    UCHAR data_context_4[28] = "what do ya want for nothing?";

    // KD_hmac_sha256 test parameter
    UCHAR kd_key_1[32] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                          0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
                          0x1f, 0x20
                         };
    const char kd_text_1[] = "pairwise key expansion for infrastructure unicast";
    UCHAR kd_out_data_1[80];

    //hmac_sha(key4, 4,  data_context_4, 28, out_data_4, 32);
    hmac_sha256(key4, 4, data_context_4, 28, out_data_4);

    kd_hmac_sha256(kd_key_1, 32, (UCHAR *)kd_text_1, strlen(kd_text_1)/*49*/, kd_out_data_1, 48);

    hex_dump("hmac_sha256 test vector 4", out_data_4, 32);
    hex_dump("KD_hmac_sha256 test vector 1", kd_out_data_1, 48);

}

// For test vector
#if 0

void print_mem(void *p, int len)
{
    int i = 0;
    unsigned char *pp = p;
    printf("\t");
    for(i=0; i<len; i++)
    {
        //printf("0x%02x, ", pp[i]);
        printf("%02x ", pp[i]);
        if((i + 1) %16 == 0)
            printf("\n\t");
    }
    printf("\n");
}

void print_mem_int(void *p, int len)
{
    int i = 0;
    unsigned int *pp = (unsigned int *)p;

    printf("\n");
    for(i=0; i<len; i++)
    {
        //printf("0x%02x, ", pp[i]);
        printf("0x%08x ", pp[i]);
        if((i + 1) %4 == 0)
            printf("\n");
    }
    printf("\n");
}

void dump_bin_int(char *name, void *data, int len)
{
    int i = 0;
    unsigned int *p = data;

    if(name != NULL)
    {
        printf("%s(%d): \n", name, len/4);
    }
    printf("\t");

    for(i=0; i<len/4; i++)
    {
        printf("%04x ", p[i]);
        if(((i+1)%4) ==0)
            printf("\n\t");
    }
    if(((i+1)%4 ) != 0)
        printf("\n");
}

void dump_bin(char *name, void *data, int len)
{
    int i = 0;
    unsigned char *p = data;

    if(name != NULL)
    {
        printf("%s(%d): \n", name, len);
    }
    printf("\t");

    for(i=0; i<len; i++)
    {
        printf("%02x ", p[i]);
        if(((i+1)%16) ==0)
            printf("\n\t");
    }
    if(((i+1)%16 ) != 0)
        printf("\n");
}

#define M_LEN  (1024)
#define ee (0.000001)
//#define CLOCKS_PER_SEC OS_HZ
INT SMS4_TEST(void)
{
    unsigned char *pt = NULL;
    unsigned char *ct = NULL;
    unsigned long start = 0;
    unsigned long stop = 0;
    int i = 0;
    int counts = 1;
    float  usetimes;
    char tmpstr[] ="a";
    int str_len = 0;
    int ret = 0;
    unsigned char key0[16] = {  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
                             };
    unsigned char pt1[16]   = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
                              };
    unsigned char iv1[16]    = {    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
                               };
    unsigned char *key = (unsigned char *)key0;
    unsigned char enkey[128];
    unsigned char ofbct[64];
    unsigned char ofbdect[64];
    unsigned char cbcmac[16];
#if 0
    {
        //ct_msk - hexdump(len=16):
        unsigned char ct_msk[16]= {  0x40, 0xa1, 0x33, 0x70, 0x70, 0xcb, 0xe5, 0x95,
                                     0x8a, 0x1d, 0x82, 0xb4, 0xb9, 0xcd, 0xf8, 0xea
                                  };

        //kek - hexdump(len=16):
        unsigned char  kek[16]= {    0xF3, 0x23, 0x63, 0x89, 0xC3, 0xF2, 0xE5, 0x49,
                                     0xAA, 0x76, 0x51, 0x94, 0x28, 0xFC, 0x62, 0x06
                                };


        //iv - hexdump(len=16):
        unsigned char  iv_t[16]= {   0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36,
                                     0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36
                                 };

        printf("-------------------------------------------------\n");
        dump_bin("kek",kek, 16);
        SMS4KeyExt(kek, (unsigned int *)enkey, 0);
        dump_bin("dekey", enkey, 128);
        dump_bin_int("dekey", enkey, 128);
        dump_bin("kek",kek, 16);
        dump_bin("iv_t", iv_t, 16);

        memset(ofbct, 0, 64);
        ret = wpi_decrypt(iv_t, ct_msk, 16, kek, ct_msk);
        dump_bin("pt_msk",ct_msk, 16);
    }
#endif
    printf("--------------------KEY EXT-----------------------\n");
    dump_bin("key",key, 16);
    SMS4KeyExt(key, (unsigned int *)enkey, 0);
    dump_bin("enkey", enkey, 128);
    dump_bin_int("enkey", enkey, 128);
    dump_bin("key",key, 16);
    dump_bin("OFBIV1", iv1, 16);

    printf("-------------------CBC-------------------------\n");
    memset(cbcmac, 0, 16);
    ret = wpi_pmac(iv1, pt1, 1, key, cbcmac);
    dump_bin("cbcpt", pt1, 16);
    dump_bin("cbcmac", cbcmac, 16);

    printf("-------------------OFB-------------------------\n");
    memset(ofbct, 0, 64);
    ret = wpi_encrypt(iv1, pt1, 16, key, ofbct);
    dump_bin("pt1",pt1, 16);
    dump_bin("ct1",ofbct, 16);

    ret = wpi_decrypt(iv1, ofbct, 16, key, ofbdect);
    dump_bin("ct1",ofbct, 16);
    dump_bin("dect1",ofbdect, 16);
    printf("-------------------------------------------------\n");

    memset(ofbct, 0, 64);
    ret = wpi_encrypt(iv1, pt1, 4, key, ofbct);
    dump_bin("pt2", pt1, 4);
    dump_bin("ct2", ofbct, 4);

    memset(ofbdect, 0, 64);
    ret = wpi_decrypt(iv1, ofbct, 4, key, ofbdect);
    dump_bin("ofbct2",ofbct, 4);
    dump_bin("dect2",ofbdect, 4);

    return 1;

}



#endif

#if 0
VOID cert_test(PRTMP_ADAPTER    pAd)
{
    char    tmpBuf[256];
    UCHAR   asue_addr[6] = {0x00, 0x0E, 0x2E, 0xC3, 0x5B, 0x60};
    UCHAR   ae_addr[6] = {0x00, 0x0E, 0x2E, 0xC3, 0x5B, 0x50};
    UCHAR   sendto_asue[1500] = {0};
    UCHAR   sendto_as[1500] = {0};
    UCHAR   sendto_ae[1500] = {0};
    USHORT  sendto_asue_len = 0;
    USHORT  sendto_ae_len = 0;
    USHORT  sendto_as_len = 0;
    STA_TABLE_ENTRY  *pEntry = NULL;
    UCHAR   ae_auth_flag[32];
    UCHAR   asue_auth_flag[32];
    UCHAR   asue_challenge[32];

    memset(tmpBuf, 0, 256);
    memset(pAd->cert_info.config.cert_name, 0, 256);
    sprintf(tmpBuf, "%s", "/etc/user.cer");
    os_memcpy(pAd->cert_info.config.cert_name, tmpBuf, strlen(tmpBuf));

    memset(tmpBuf, 0, 256);
    memset(pAd->cert_info.config.as_name, 0, 256);
    sprintf(tmpBuf, "%s", "/etc/as.cer");
    os_memcpy(pAd->cert_info.config.as_name, tmpBuf, strlen(tmpBuf));

    memset(tmpBuf, 0, 256);
    memset(pAd->cert_info.config.ae_name, 0, 256);
    sprintf(tmpBuf, "%s", "/etc/ae.cer");
    os_memcpy(pAd->cert_info.config.ae_name, tmpBuf, strlen(tmpBuf));

    pAd->cert_info.config.used_cert = 1;

    if(strlen(pAd->cert_info.config.cert_name))
    {
        INT32   res;

        res = wapi_register_certificate(pAd);

        ap_initialize_signature_alg(pAd);

        wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->user_cert_st,
                                &(pAd->local_user_id),
                                pAd->cert_info.config.used_cert);
        printf("local user id\n");
        DPrint_string(pAd->local_user_id.id_data, pAd->local_user_id.id_len);

        wai_fixdata_id_by_ident(pAd->cert_info.local_cert_obj->asu_cert_st,
                                &(pAd->asu_id),
                                pAd->cert_info.config.used_cert);
        printf("asu id\n");
        DPrint_string(pAd->asu_id.id_data, pAd->asu_id.id_len);

        wai_initialize_ecdh(&pAd->local_ecdh);
    }

    // Look up the STA info
    pEntry = StaTableLookup(pAd, asue_addr);

    // If the STA doesn't exist, insert it to table
    if (pEntry == NULL)
        pEntry = StaTableInsertEntry(pAd, asue_addr, 0);

    memset(sendto_asue, 0x00, 1500);

    sendto_asue_len++;

    os_get_random(ae_auth_flag, NONCE_LEN);
    memcpy(sendto_asue + sendto_asue_len, ae_auth_flag, 32);
    sendto_asue_len += 32;

    if (wapi_auth_activate_create(pAd, asue_addr, sendto_asue, &sendto_asue_len) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_auth_activate_create fail !!!\n");
        goto err;
    }

    if (wapi_auth_activate_check(pAd, ae_addr, sendto_asue, sendto_asue_len) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_auth_activate_check fail !!!\n");
        goto err;
    }


    memset(sendto_ae, 0x00, 1500);
    sendto_ae_len++;

    //get_random(asue_auth_flag, 32);
    os_get_random(asue_auth_flag, NONCE_LEN);
    memcpy(sendto_ae + sendto_ae_len, asue_auth_flag, 32);
    sendto_ae_len += 32;

    //get_random(asue_challenge, 32);
    os_get_random(asue_challenge, NONCE_LEN);
    memcpy(sendto_ae + sendto_ae_len, asue_challenge, 32);
    sendto_ae_len += 32;

    if (wapi_access_auth_request_create(pAd, ae_addr, sendto_ae, &sendto_ae_len) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_access_auth_request_create fail !!!\n");
        goto err;
    }

    if (wapi_access_auth_request_check(pAd, asue_addr, sendto_ae, sendto_ae_len) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_access_auth_request_check fail !!!\n");
        goto err;
    }

    memset(sendto_as, 0x00, 1500);
    if (wapi_certificate_auth_request_create(pAd, asue_addr, sendto_as, &sendto_as_len) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_certificate_auth_request_create fail !!!\n");
        goto err;
    }

    if (wapi_client_send(pAd, sendto_as, sendto_as_len) != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "wapi_client_send fail !!!\n");
        goto err;
    }

err:
    return;
}
#endif

int main(int argc, char *argv[])
{
    PRTMP_ADAPTER pAd;
    pid_t child_pid;
    int ret = 1;
    int c;
    pid_t auth_pid;
    char ifname[IFNAMSIZ+1];
    int  ifname_len;

    // assign default wireless interface name
    strcpy(ifname, "ra0");
    ifname_len = 3;

    for (;;)
    {
        c = getopt(argc, argv, "d:i:h");
        if (c < 0)
            break;

        switch (c)
        {
            case 'd':
                /*  set Debug level -
                        RT_DEBUG_OFF        0
                        RT_DEBUG_ERROR      1
                        RT_DEBUG_WARN       2
                        RT_DEBUG_TRACE      3
                        RT_DEBUG_INFO       4
                */
                printf("Set debug level as %s\n", optarg);
                RTDebugLevel = (int)strtol(optarg, 0, 10);
                break;

            case 'i':
                // Assign the wireless interface when support multiple cards
                //sprintf(prefix_name, "%s%02d_", prefix_name, ((int)strtol(optarg, 0, 10) - 1));

                // Assign a specific interface name
                strcpy(ifname, optarg);
                ifname_len = strlen(ifname);
                break;

            case 'h':
            default:
                usage();
                break;
        }
    }

    DBGPRINT(RT_DEBUG_TRACE, "Ralink WAPI daemon, version = '%s' \n", wapid_version);
    DBGPRINT(RT_DEBUG_TRACE, "wireless ifname = '%s', len(%d)\n", ifname, ifname_len);

    child_pid = fork();
    if (child_pid == 0)
    {
        // Get process ID
        auth_pid = getpid();
        DBGPRINT(RT_DEBUG_TRACE, "Porcess ID = %d\n",auth_pid);

        // Allocate a memory for RTMP_ADAPTER
        pAd = os_malloc(sizeof(RTMP_ADAPTER));
        if (pAd == NULL)
        {
            DBGPRINT(RT_DEBUG_ERROR, "malloc RTMP_ADAPTER failed\n");
            exit(1);
        }

        // Initialize eloop structure
        eloop_init(pAd);

        // Register signal
        eloop_register_signal(SIGINT, Handle_term, NULL);
        eloop_register_signal(SIGTERM, Handle_term, NULL);
        eloop_register_signal(SIGUSR1, Handle_usr1, NULL);
        eloop_register_signal(SIGHUP, Handle_usr1, NULL);

        // Initialize RTMP_ADAPTER structure
        if (wapi_data_init(pAd, ifname, ifname_len) == FALSE)
            goto out;

        // Setup interface for WAPI
        if (wapi_setup_interface(pAd) == FALSE)
            goto out;

#ifdef OPENSSL_INC
        // Initialize certificate for WAPI
        if (wapi_certificate_init(pAd) == FALSE)
            goto out;
#endif // OPENSSL_INC //

        // Initialize MLME state machine
        if (MlmeInit(pAd) != NDIS_STATUS_SUCCESS)
            goto out;

        // test
        //ProcessSha();

        //ecdh test
        //cert_test(pAd);

        //SMS4_TEST();

        // Notify driver about PID
        if (RT_ioctl(pAd->ioctl_sock,
                     RT_PRIV_IOCTL,
                     (PUCHAR)&auth_pid,
                     sizeof(int),
                     pAd->MBSS[0].ifname,
                     pAd->MBSS[0].ifname_len,
                     RT_OID_802_11_WAPI_PID) != 0)
            DBGPRINT(RT_DEBUG_ERROR," ==>ioctl failed(%s)\n", pAd->MBSS[0].ifname);

        // main roution to process timer and sock handler
        eloop_run();

        // Clear the entire STA table
        StaTableReset(pAd);
        ret = 0;

    out:
        os_free(pAd->FragFrame);
        wapi_data_cleanup(pAd);
        MlmeHalt(pAd);
        os_free(pAd);

        eloop_destroy();
        closelog();

#ifdef OPENSSL_INC
        wapi_unregister_certificate();
        X509_exit();

        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_remove_state(0);
        ERR_free_strings();
        //CRYPTO_mem_leaks_fp(stderr);
#endif // OPENSSL_INC //

        return ret;
    }
    else
        return 0;
}

