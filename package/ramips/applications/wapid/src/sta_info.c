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

#include "main_def.h"

/*
    ==========================================================================
    Description:
        Look up the MAC address in the STA table. Return NULL if not found.
    Return:
        pEntry - pointer to the MAC entry; NULL is not found
    ==========================================================================
*/
STA_TABLE_ENTRY *StaTableLookup(
    IN PRTMP_ADAPTER    pAd,
    IN PUCHAR           pAddr)
{
    ULONG HashIdx;
    STA_TABLE_ENTRY *pEntry = NULL;

    HashIdx = MAC_ADDR_HASH_INDEX(pAddr);
    pEntry = pAd->StaTab.Hash[HashIdx];

    while (pEntry && (pEntry->Valid))
    {
        if (MAC_ADDR_EQUAL(pEntry->Addr, pAddr))
        {
            break;
        }
        else
        {
            pEntry = pEntry->pNext;
        }
    }

    return pEntry;
}

STA_TABLE_ENTRY *StaTableInsertEntry(
    IN  PRTMP_ADAPTER   pAd,
    IN  PUCHAR          pAddr,
    IN  UCHAR           apidx)
{
    UCHAR HashIdx;
    INT i;
    STA_TABLE_ENTRY *pEntry = NULL, *pCurrEntry;

    // Check if the table is full
    if (pAd->StaTab.Size >= MAX_STA_NUM)
        return NULL;

    // allocate one STA entry
    for (i = 1; i< MAX_STA_NUM; i++)
    {
        // pick up the first available vacancy
        if (pAd->StaTab.Content[i].Valid == FALSE)
        {
            pEntry = &pAd->StaTab.Content[i];

            pEntry->Valid = TRUE;
            pEntry->Aid = (USHORT)i;
            pEntry->apidx = apidx;

            os_memcpy(pEntry->Addr, pAddr, MAC_ADDR_LEN);

            // Reset the WAI state
            pEntry->WaiAuthState = WAI_CERT_AUTH_IDLE;
            pEntry->WaiKeyState = WAI_UCAST_KEY_IDLE;

            // set the security information
            pEntry->AuthMode = pAd->MBSS[apidx].AuthMode;
            pEntry->UniEncrypType = pAd->MBSS[apidx].UniEncrypType;
            pEntry->MultiEncrypType = pAd->MBSS[apidx].MultiEncrypType;
            pEntry->PortSecured = WAPI_PORT_NOT_SECURED;    // default as port not secured
            pEntry->USKID = 0;

            // init sequence
            pEntry->frame_seq = 1;

            if (pEntry->AuthMode == WAPI_AUTH_PSK)
                os_memcpy(pEntry->BK, pAd->MBSS[apidx].BK, 16);

            pAd->StaTab.Size ++;

            DBGPRINT(RT_DEBUG_TRACE, "StaTableInsertEntry - allocate entry(%02x:%02x:%02x:%02x:%02x:%02x) #%d, Total= %d \n", MAC2STR(pEntry->Addr), i, pAd->StaTab.Size);

            break;
        }
    }

    // add this STA entry into HASH table
    if (pEntry)
    {
        HashIdx = MAC_ADDR_HASH_INDEX(pAddr);
        if (pAd->StaTab.Hash[HashIdx] == NULL)
        {
            pAd->StaTab.Hash[HashIdx] = pEntry;
        }
        else
        {
            pCurrEntry = pAd->StaTab.Hash[HashIdx];
            while (pCurrEntry->pNext != NULL)
                pCurrEntry = pCurrEntry->pNext;
            pCurrEntry->pNext = pEntry;
        }
    }

    return pEntry;
}


/*
    ==========================================================================
    Description:
        Delete a specified client from STA table


    ==========================================================================
 */
BOOLEAN StaTableDeleteEntry(
    IN PRTMP_ADAPTER pAd,
    IN USHORT wcid,
    IN PUCHAR pAddr)
{
    USHORT HashIdx;
    STA_TABLE_ENTRY *pEntry, *pPrevEntry, *pProbeEntry;

    if (wcid >= MAX_STA_NUM)
        return FALSE;

    HashIdx = MAC_ADDR_HASH_INDEX(pAddr);
    pEntry = &pAd->StaTab.Content[wcid];

    if (pEntry && (pEntry->Valid))
    {
        if (MAC_ADDR_EQUAL(pEntry->Addr, pAddr))
        {
            DBGPRINT(RT_DEBUG_TRACE, "StaTableDeleteEntry("MACSTR")\n", MAC2STR(pAddr));
			
			// Find the entry through hash table
			pPrevEntry = NULL;
			pProbeEntry = pAd->StaTab.Hash[HashIdx];
			ASSERT(pProbeEntry);

			// update Hash list
			do
			{
				if (pProbeEntry == pEntry)
				{
					if (pPrevEntry == NULL)
					{
						pAd->StaTab.Hash[HashIdx] = pEntry->pNext;
					}
					else
					{
						pPrevEntry->pNext = pEntry->pNext;
					}
					break;
				}

				pPrevEntry = pProbeEntry;
				pProbeEntry = pProbeEntry->pNext;
			} while (pProbeEntry);

			// not found !!!
			ASSERT(pProbeEntry != NULL);
			
   			NdisZeroMemory(pEntry, sizeof(STA_TABLE_ENTRY));
			pAd->StaTab.Size --;
			DBGPRINT(RT_DEBUG_TRACE, "StaTableDeleteEntry: the remaining STA num is %d in table \n", pAd->StaTab.Size);
		}
		else
		{
			DBGPRINT(RT_DEBUG_WARN, "\n%s: Impossible Wcid = %d !!!!!\n", __FUNCTION__, wcid);			
		}
	}
		
	return TRUE;
}


/*
	==========================================================================
	Description:
		This routine reset the entire MAC table. 
		
	==========================================================================
 */
VOID StaTableReset(
	IN  PRTMP_ADAPTER  pAd)
{
	int         i;
	
	DBGPRINT(RT_DEBUG_TRACE, "StaTableReset ==>\n");
	

	for (i=1; i<MAX_STA_NUM; i++)
	{
		if (pAd->StaTab.Content[i].Valid == TRUE)
		{			        												
			// need to notify driver ?			
		}
	}

	// clear all entire table
	NdisZeroMemory(&pAd->StaTab, sizeof(STA_TABLE));
	
	return;
}


