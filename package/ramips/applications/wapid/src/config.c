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
    config.c

    Revision History:
    Who             When            What
    --------        ----------      ----------------------------------------------
    Albert Yang     2008/4/10       configuration setting

*/

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "main_def.h"
#include "config.h"
#include "sha256.h"
#include "sms4.h"
#include "wpi_pcrypt.h"

#ifdef OPENSSL_INC
#include "cert_auth.h"
#include "alg_comm.h"
#endif // OPENSSL_INC //

#define LOOPBACK_IP "127.0.0.1"

const char *GetAuthMode(CHAR auth)
{
    if(auth == WAPI_AUTH_DISABLE)
        return "OPEN";
    if(auth == WAPI_AUTH_PSK)
        return "WAPI-PSK";
    if(auth == WAPI_AUTH_CERT)
        return "WAPI-CERT";

    return "UNKNOW";
}


BOOLEAN ap_initialize_signature_alg(
    IN PRTMP_ADAPTER    pAd)
{
    char alg_para_oid_der[16] = {0x06, 0x09,0x2a,0x81,0x1c, 0xd7,0x63,0x01,0x01,0x02,0x01};

    memset((UCHAR *)&(pAd->sign_alg), 0, sizeof(wai_fixdata_alg));
    pAd->sign_alg.alg_length = 16;
    pAd->sign_alg.sha256_flag = 1;
    pAd->sign_alg.sign_alg = 1;
    pAd->sign_alg.sign_para.para_flag = 1;
    pAd->sign_alg.sign_para.para_len = 11;
    memcpy(pAd->sign_alg.sign_para.para_data, alg_para_oid_der, 11);
    return 0;
}

VOID config_init(
    PRTMP_ADAPTER   pAd,
    PUCHAR          pIfName,
    INT             ifname_len)
{
    INT     i;
    const char KEY_NOTIFY_IV[16] = {0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c,
                                    0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c
                                   };

    // initialize variable
    os_memcpy((char *)pAd->wapi_ifname, "br0", 3);
    os_memcpy((char *)pAd->preauth_ifname, "br0", 3);

    pAd->mbss_num = 1;
    os_memset(&pAd->MBSS, 0, MAX_MBSSID_NUM * sizeof(MULTI_BSS));

    // assign the first BSS interface name
    os_memcpy(pAd->MBSS[0].ifname, pIfName, ifname_len);
    pAd->MBSS[0].ifname_len = ifname_len;

    pAd->cert_info.config.used_cert = 0;

    for (i = 0; i < MAX_MBSSID_NUM; i++)
    {
        pAd->MBSS[i].AuthMode = WAPI_AUTH_DISABLE;
        pAd->MBSS[i].UniEncrypType = WAPI_ENCRYPT_DISABLE;
        pAd->MBSS[i].MultiEncrypType = WAPI_ENCRYPT_DISABLE;

        os_memcpy(pAd->MBSS[i].KeyNotifyIv, KEY_NOTIFY_IV, 16);
    }

#if 0
    INT i;
    //INT32 wapi_auth_mode = WAPI_AUTH_DISABLE;


    pAd->mbss_num = 1;  // temporary by AlbertY
    os_memset(&pAd->MBSS, 0, MAX_MBSSID_NUM * sizeof(MULTI_BSS));
    pAd->cert_info.config.used_cert = 0;

    for (i = 0; i < pAd->mbss_num; i++)
    {
        char    tmpBuf[IFNAMSIZ+1];
        const char Default_WIE[22] = {0x44,                         /* element ID */
                                      0x14,                         /* length */
                                      0x01, 0x00,                   /* version */
                                      0x01, 0x00,                   /* AKM count */
                                      0x00, 0x14, 0x72, 0x01,       /* AKM suite */
                                      0x01, 0x00,                   /* unicast suite count */
                                      0x00, 0x14, 0x72, 0x01,       /* unicast suite */
                                      0x00, 0x14, 0x72, 0x01,       /* broadcast suite */
                                      0x00, 0x00
                                     };                  /* WAPI capability */

        const char KEY_NOTIFY_IV[16] = {0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36,
                                        0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36
                                       };
        const char group_prefix[100] = "multicast or station key expansion for station unicast and multicast and broadcast";

        sprintf(tmpBuf, "%s%d", pPreFixName, i);

        os_memcpy(pAd->MBSS[i].ifname, tmpBuf, strlen(tmpBuf));
        pAd->MBSS[i].ifname[strlen(tmpBuf)] = '\0';
        pAd->MBSS[i].ifname_len = strlen(tmpBuf);

        //pAd->MBSS[i].AuthMode = WAPI_AUTH_PSK;
        pAd->MBSS[i].AuthMode = WAPI_AUTH_CERT;
        pAd->MBSS[i].UniEncrypType = WAPI_ENCRYPT_SMS4;
        pAd->MBSS[i].MultiEncrypType = WAPI_ENCRYPT_SMS4;

        pAd->MBSS[i].WAPI_PSK_len = 8;
        os_memcpy(pAd->MBSS[i].WAPI_PSK, "11111111", pAd->MBSS[i].WAPI_PSK_len);

        // Calculate the BK in Pre-Shared Key mode
        if (pAd->MBSS[i].AuthMode == WAPI_AUTH_PSK)
        {
            const char PSK_context[]= "preshared key expansion for authentication and key negotiation";

            kd_hmac_sha256(pAd->MBSS[i].WAPI_PSK,
                           pAd->MBSS[i].WAPI_PSK_len,
                           (UCHAR *)PSK_context,
                           strlen(PSK_context),
                           pAd->MBSS[i].BK,
                           16);
#if 0
            {
                UCHAR ADDID[12]     = {0x0A, 0x0B, 0xC0, 0x02, 0x31, 0xD3, 0x00, 0x0B, 0xC0, 0x03, 0x04, 0xA6};
                UCHAR test_bk_id[16];

                printf("strlen(PSK_context)=%d\n",strlen(PSK_context));
                hex_dump("BK", pAd->MBSS[i].BK, 16);
                //hex_dump("BK_1", pAd->MBSS[i].BK_1, 16);
                kd_hmac_sha256(pAd->MBSS[i].BK, 16, ADDID, 12, test_bk_id, 16);
                hex_dump("TEST-BKID", test_bk_id, 16);
            }
#endif
        }
        else if (pAd->MBSS[i].AuthMode == WAPI_AUTH_CERT)
        {
            char cert_path[256];

            //wapi_auth_mode = WAPI_AUTH_CERT;

            memset(cert_path, 0, 256);
            memset(pAd->cert_info.config.as_name, 0, 256);
            sprintf(cert_path, "%s", "/etc/as.cer");
            os_memcpy(pAd->cert_info.config.as_name, cert_path, strlen(cert_path));
            pAd->cert_info.config.as_name[strlen(cert_path)] = '\0';

            memset(cert_path, 0, 256);
            memset(pAd->cert_info.config.ae_name, 0, 256);
            sprintf(cert_path, "%s", "/etc/user.cer");
            os_memcpy(pAd->cert_info.config.ae_name, cert_path, strlen(cert_path));
            pAd->cert_info.config.ae_name[strlen(cert_path)] = '\0';

            pAd->cert_info.config.used_cert = 1;
        }

        // Generate NMK and its related key information
        os_get_random(pAd->MBSS[i].NMK, 16);
        os_memcpy(pAd->MBSS[i].KeyNotifyIv, KEY_NOTIFY_IV, 16);

#if 0
        {
            hex_dump("1. ctx", pAd->MBSS[i].NMK, 16);
            wpi_encrypt(pAd->MBSS[i].KeyNotifyIv,
                        pAd->MBSS[i].NMK,
                        16,
                        pAd->MBSS[i].BK,
                        pAd->MBSS[i].NMK);

            printf("--- wpi_encrypt --- \n");
            //hex_dump("iv", iv1, 16);
            //hex_dump("ctx", pAd->MBSS[i].NMK, 16);
            //hex_dump("key", key, 16);
            hex_dump("en_out", pAd->MBSS[i].NMK, 16);


            // Decrypt the key_data field
            wpi_decrypt(pAd->MBSS[i].KeyNotifyIv,
                        pAd->MBSS[i].NMK,
                        16,
                        pAd->MBSS[i].BK,
                        pAd->MBSS[i].NMK);

            printf("--- wpi_decrypt --- \n");
            //hex_dump("iv", iv1, 16);
            //hex_dump("ctx", pAd->MBSS[i].NMK, 16);
            //hex_dump("key", key, 16);
            hex_dump("de_out", pAd->MBSS[i].NMK, 16);

        }
#endif
        hex_dump("NMK", pAd->MBSS[i].NMK, 16);
        // Generate GTK per BSS
        kd_hmac_sha256(pAd->MBSS[i].NMK,
                       16,
                       (UCHAR *)group_prefix,
                       strlen(group_prefix),
                       pAd->MBSS[i].GTK,
                       32);

        // Set group key to driver
        wapi_set_mcast_key_proc(pAd, pAd->MBSS[i].GTK, i);

        // Fill in WIE and its length
        os_memcpy(pAd->MBSS[i].WIE, Default_WIE, 22);
        pAd->MBSS[i].WIE_Len = 22;

    }
#endif

}

BOOLEAN config_read(
    PRTMP_ADAPTER   pAd,
    PUCHAR          pIfName,
    INT             ifname_len)
{
    INT                 i;
    PWAPI_CONF          pWapiConf;
    PCOMMON_WAPI_INFO   pWapiCommConf;
    PUCHAR              buf_ptr;
    UINT                buf_len;
    const char  psk_context[]= "preshared key expansion for authentication and key negotiation";
    INT idx;


    // initialize configuration
    config_init(pAd, pIfName, ifname_len);

    // allocate memory to query configuration from driver
    buf_len = sizeof(WAPI_CONF);
    buf_ptr = os_malloc(buf_len + 1);
    if (buf_ptr == NULL)
    {
        DBGPRINT(RT_DEBUG_ERROR, "malloc() failed for config_init(len=%d)\n", buf_len);
        return FALSE;
    }
    else
    {
        DBGPRINT(RT_DEBUG_TRACE, "alloc memory(%d) for config_init. \n", buf_len);
        os_memset(buf_ptr, 0, buf_len);
    }

    if ((RT_ioctl(pAd->ioctl_sock,
                  RT_PRIV_IOCTL,
                  buf_ptr,
                  buf_len,
                  pAd->MBSS[0].ifname,
                  pAd->MBSS[0].ifname_len,
                  OID_802_11_WAPI_CONFIGURATION)) != 0)
    {
        DBGPRINT(RT_DEBUG_ERROR,"ioctl failed for config_read(len=%d, ifname=%s)\n", pAd->MBSS[0].ifname_len, pAd->MBSS[0].ifname);
        os_free(buf_ptr);
        return FALSE;
    }

    pWapiConf = (PWAPI_CONF)buf_ptr;

    // MBSS number
    pAd->mbss_num = pWapiConf->mbss_num;
    if(pAd->mbss_num > MAX_MBSSID_NUM)
        pAd->mbss_num = 1;
    DBGPRINT(RT_DEBUG_TRACE, "MBSS number: %d\n", pAd->mbss_num);

    pWapiCommConf = &pWapiConf->comm_wapi_info;

    // common wapi configuration
    // wapi interface
    if (pWapiCommConf->wapi_ifname_len > 0)
    {
        os_memcpy(pAd->wapi_ifname, pWapiCommConf->wapi_ifname, pWapiCommConf->wapi_ifname_len);
        pAd->wapi_ifname[pWapiCommConf->wapi_ifname_len] = '\0';
        DBGPRINT(RT_DEBUG_TRACE, "wapi ifname(%s) \n", pAd->wapi_ifname);
    }

    // pre-auth interface
    if (pWapiCommConf->preauth_ifname_len > 0)
    {
        os_memcpy(pAd->preauth_ifname, pWapiCommConf->preauth_ifname, pWapiCommConf->preauth_ifname_len);
        pAd->preauth_ifname[pWapiCommConf->preauth_ifname_len] = '\0';
        DBGPRINT(RT_DEBUG_TRACE, "pre-auth ifname(%s) \n", pAd->preauth_ifname);
    }

#if 0
    // AS certificate path
    if (pWapiCommConf->as_cert_path_len > 0)
    {
        os_memcpy(pAd->cert_info.config.as_name, pWapiCommConf->as_cert_path, pWapiCommConf->as_cert_path_len);
        pAd->cert_info.config.as_name[pWapiCommConf->as_cert_path_len] = '\0';
        DBGPRINT(RT_DEBUG_TRACE, "AS certificate path(%s) \n", pAd->cert_info.config.as_name);
    }
#endif
    // AS certificate path
    pAd->cert_info.config.as_no = pWapiCommConf->as_cert_no;
    DBGPRINT(RT_DEBUG_TRACE, "AS number(%d) \n", pAd->cert_info.config.as_no);

    for(idx=0; idx<pWapiCommConf->as_cert_no; idx++)
    {
        if (pWapiCommConf->as_cert_path_len[idx] > 0)
        {
            os_memcpy(pAd->cert_info.config.as_name[idx], pWapiCommConf->as_cert_path[idx], pWapiCommConf->as_cert_path_len[idx]);
            pAd->cert_info.config.as_name[idx][pWapiCommConf->as_cert_path_len[idx]] = '\0';
            DBGPRINT(RT_DEBUG_TRACE, "AS certificate path%d(%s) \n", idx+1, pAd->cert_info.config.as_name[idx]);
        }
    }

    // CA certificate path
    if (pWapiCommConf->ca_cert_path_len > 0)
    {
        os_memcpy(pAd->cert_info.config.ca_name, pWapiCommConf->ca_cert_path, pWapiCommConf->ca_cert_path_len);
        pAd->cert_info.config.ca_name[pWapiCommConf->ca_cert_path_len] = '\0';
        pAd->cert_info.config.cert_mode = THREE_CERTIFICATE_MODE;
        DBGPRINT(RT_DEBUG_TRACE, "CA certificate path(%s) \n", pAd->cert_info.config.ca_name);
    }
    else
        pAd->cert_info.config.cert_mode = TWO_CERTIFICATE_MODE;

    // user certificate path
    if (pWapiCommConf->user_cert_path_len > 0)
    {
        os_memcpy(pAd->cert_info.config.ae_name, pWapiCommConf->user_cert_path, pWapiCommConf->user_cert_path_len);
        pAd->cert_info.config.ae_name[pWapiCommConf->user_cert_path_len] = '\0';
        DBGPRINT(RT_DEBUG_TRACE, "user certificate path(%s) \n", pAd->cert_info.config.ae_name);
    }

    // assign the ip address of authentication server
    // Todo check if use the external AS
    pAd->auth_server.as_addr.s_addr = pWapiCommConf->wapi_as_ip;
    if (pAd->auth_server.as_addr.s_addr != 0)
    {
        DBGPRINT(RT_DEBUG_TRACE, "AS IP Address : '%s'(%x)\n",
                 inet_ntoa(pAd->auth_server.as_addr),
                 pAd->auth_server.as_addr.s_addr);
    }
    else
    {
        // use the loopback address
        inet_aton(LOOPBACK_IP, &pAd->auth_server.as_addr);
    }

    // assign the port of authentication server
    pAd->auth_server.as_port = pWapiCommConf->wapi_as_port;
    if (pAd->auth_server.as_port == 0)
        pAd->auth_server.as_port = 3810; // default port value
    else
        DBGPRINT(RT_DEBUG_TRACE, "AS port : %d \n", pAd->auth_server.as_port);

    // wapi configuration for MBSS
    for (i = 0; i < pAd->mbss_num; i++)
    {
        PMBSS_WAPI_INFO pMbssInfo;

        pMbssInfo = &pWapiConf->mbss_wapi_info[i];

        // assign wireless interface name except the first BSS
        if (pMbssInfo->ifname_len > 0)
        {
            if (i > 0)
            {
                os_memcpy(pAd->MBSS[i].ifname, pMbssInfo->ifname, pMbssInfo->ifname_len);
                pAd->MBSS[i].ifname_len = pMbssInfo->ifname_len;
            }
            DBGPRINT(RT_DEBUG_TRACE, "BSS%d, ifname(%s) \n", i, pAd->MBSS[i].ifname);
        }

        // assign authentication mode and encryption type
        pAd->MBSS[i].AuthMode = pMbssInfo->auth_mode;
        if (pAd->MBSS[i].AuthMode != WAPI_AUTH_DISABLE)
        {
            pAd->MBSS[i].UniEncrypType = WAPI_ENCRYPT_SMS4;
            pAd->MBSS[i].MultiEncrypType = WAPI_ENCRYPT_SMS4;
        }
        DBGPRINT(RT_DEBUG_TRACE, "BSS%d, auth(%d)=%s \n", i, pAd->MBSS[i].AuthMode, GetAuthMode(pAd->MBSS[i].AuthMode));

        // assign the pre-shared key
        if (pMbssInfo->psk_len > 0)
        {
            os_memcpy(pAd->MBSS[i].WAPI_PSK, pMbssInfo->psk, pMbssInfo->psk_len);
            pAd->MBSS[i].WAPI_PSK_len = pMbssInfo->psk_len;
            DBGPRINT(RT_DEBUG_TRACE, "BSS%d ", i);
            hex_dump("PSK key", pAd->MBSS[i].WAPI_PSK, pAd->MBSS[i].WAPI_PSK_len);
        }
        else
        {
            // check if the pre-shared key exists in PSK mode.
            if (pAd->MBSS[i].AuthMode == WAPI_AUTH_PSK)
            {
                DBGPRINT(RT_DEBUG_ERROR, "[Config ERROR] In BSS%d, the pre-shared key is empty in WAPI_AUTH_PSK.\n", i);
                os_free(buf_ptr);
                return FALSE;
            }
        }

        // assign WIE
        if (pMbssInfo->wie_len > 0)
        {
            os_memcpy(pAd->MBSS[i].WIE, pMbssInfo->wie, pMbssInfo->wie_len);
            pAd->MBSS[i].WIE_Len = pMbssInfo->wie_len;
            DBGPRINT(RT_DEBUG_TRACE, "BSS%d \n", i);
            hex_dump("WIE", pAd->MBSS[i].WIE, pAd->MBSS[i].WIE_Len);
        }
        else
        {
            if (pAd->MBSS[i].AuthMode != WAPI_AUTH_DISABLE)
            {
                DBGPRINT(RT_DEBUG_ERROR, "[Config ERROR] In BSS%d, the WIE is empty.\n", i);
                os_free(buf_ptr);
                return FALSE;
            }
        }

        // Calculate the BK in PSK mode
        if (pAd->MBSS[i].AuthMode == WAPI_AUTH_PSK)
        {
            kd_hmac_sha256(pAd->MBSS[i].WAPI_PSK,
                           pAd->MBSS[i].WAPI_PSK_len,
                           (UCHAR *)psk_context,
                           strlen(psk_context),
                           pAd->MBSS[i].BK,
                           16);
        }
        else if (pAd->MBSS[i].AuthMode == WAPI_AUTH_CERT)
        {
            pAd->cert_info.config.used_cert = 1;
        }

#if 0
        if (pAd->MBSS[i].AuthMode != WAPI_AUTH_DISABLE)
        {
            const char KEY_NOTIFY_IV[16] = {0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36,
                                            0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36, 0x5c, 0x36
                                           };
            const char group_context[100] = "multicast or station key expansion for station unicast and multicast and broadcast";


            // Generate NMK and its related key information
            os_get_random(pAd->MBSS[i].NMK, 16);
            //hex_dump("NMK", pAd->MBSS[i].NMK, 16);

            os_memcpy(pAd->MBSS[i].KeyNotifyIv, KEY_NOTIFY_IV, 16);
            // Generate GTK per BSS
            kd_hmac_sha256(pAd->MBSS[i].NMK,
                           16,
                           (UCHAR *)group_context,
                           strlen(group_context),
                           pAd->MBSS[i].GTK,
                           32);

            // Set group key to driver
            //wapi_set_mcast_key_proc(pAd, pAd->MBSS[i].GTK, i);
        }
#endif

    }

    os_free(buf_ptr);
    return TRUE;

}

