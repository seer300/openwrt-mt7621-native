
/*
 ***************************************************************************
 * MediaTek Inc. 
 *
 * All rights reserved. source code is an unpublished work and the
 * use of a copyright notice does not imply otherwise. This source code
 * contains confidential trade secret material of MediaTek. Any attemp
 * or participation in deciphering, decoding, reverse engineering or in any
 * way altering the source code is stricitly prohibited, unless the prior
 * written consent of MediaTek, Inc. is obtained.
 ***************************************************************************

    Module Name:
    	bndstrg.c
*/
#include <stdlib.h>
#include <stdio.h>
#include "bndstrg.h"

int DebugLevel = DEBUG_TRACE;

//extern struct bndstrg_drv_ops bndstrg_drv_ranl_ops;

extern struct bndstrg_drv_ops bndstrg_drv_wext_ops;

int bndstrg_update_entry_statistics(
		struct bndstrg_entry_stat *statistics,
		char Rssi,
		u8 FrameSubType)
{
	int ret_val = BND_STRG_SUCCESS;

	statistics->Rssi = Rssi;
	switch (FrameSubType)
	{
		case APMT2_PEER_PROBE_REQ:
			break;
			
		case APMT2_PEER_AUTH_REQ:
			statistics->AuthReqCount++;
			break;
			
		default:
			BND_STRG_DBGPRINT(DEBUG_OFF,
			"%s(): Unexpect FrameSubType (%u)\n",
			__FUNCTION__, FrameSubType);
			ret_val = BND_STRG_UNEXP;
			break;
	}

	return ret_val;
}

struct bndstrg_cli_entry* bndstrg_table_lookup(struct bndstrg_cli_table *table, unsigned char *pAddr)
{
	unsigned long HashIdx;
	struct bndstrg_cli_entry *entry = NULL;
	
	HashIdx = MAC_ADDR_HASH_INDEX(pAddr);
	entry = table->Hash[HashIdx];

	while (entry && entry->bValid)
	{
		if (MAC_ADDR_EQUAL(entry->Addr, pAddr))
			break;
		else
			entry = entry->pNext;
	}

	return entry;
}

void get_current_system_tick(
	struct timespec *now)
{
	clock_gettime(CLOCK_REALTIME, now);
}


int bndstrg_insert_entry(
	struct bndstrg_cli_table *table,
	unsigned char *pAddr,
	struct bndstrg_cli_entry **entry_out)
{
	int i;
	unsigned char HashIdx;
	struct bndstrg_cli_entry *entry = NULL, *this_entry = NULL;
	int ret_val = BND_STRG_SUCCESS;

	if (table->Size >= BND_STRG_MAX_TABLE_SIZE) {
		DBGPRINT(DEBUG_WARN, "%s(): Table is full!\n", __FUNCTION__);
		return BND_STRG_TABLE_FULL;
	}

	//NdisAcquireSpinLock(&table->Lock);
	for (i = 0; i< BND_STRG_MAX_TABLE_SIZE; i++)
	{
		entry = &table->Entry[i];

		/* pick up the first available vacancy*/
		if (entry->bValid == FALSE)	{
			memset(entry, 0, sizeof(struct bndstrg_cli_entry));
			/* Fill Entry */
			get_current_system_tick(&entry->tp);
			memcpy(entry->Addr, pAddr, MAC_ADDR_LEN);
			entry->TableIndex = i;
			entry->bValid = TRUE;
			break;
		}
	}

	if (entry) {
		/* add this MAC entry into HASH table */
		HashIdx = MAC_ADDR_HASH_INDEX(pAddr);
		if (table->Hash[HashIdx] == NULL) {
			table->Hash[HashIdx] = entry;
		} else {
			this_entry = table->Hash[HashIdx];
			while (this_entry->pNext != NULL) {
				this_entry = this_entry->pNext;
			}
			this_entry->pNext = entry;
		}
		
		*entry_out = entry;
		table->Size++;
	}
	//NdisReleaseSpinLock(&table->Lock);

	BND_STRG_DBGPRINT(DEBUG_INFO,
			"%s(): Index=%u, %02x:%02x:%02x:%02x:%02x:%02x, "
			"Table Size = %u\n",
			__FUNCTION__, i, PRINT_MAC(pAddr), table->Size);

	return ret_val;
}

int bndstrg_delete_entry(struct bndstrg_cli_table *table, unsigned char *pAddr, u32 Index)
{
	u16 HashIdx;
	struct bndstrg_cli_entry *entry, *pre_entry, *this_entry;
	int ret_val = BND_STRG_SUCCESS;

	BND_STRG_DBGPRINT(DEBUG_INFO,
			"%s(): Index=%u, %02x:%02x:%02x:%02x:%02x:%02x, "
			"Table Size = %u\n",
			__FUNCTION__, Index, PRINT_MAC(pAddr), table->Size);

	//NdisAcquireSpinLock(&table->Lock);
	HashIdx = MAC_ADDR_HASH_INDEX(pAddr);
	if (Index >= BND_STRG_MAX_TABLE_SIZE)
	{
		entry = table->Hash[HashIdx];
		while (entry) {
			if (MAC_ADDR_EQUAL(pAddr, entry->Addr)) {
				/* this is the entry we're looking for */
				break;
			} else {
				entry = entry->pNext;
			}
		}

		if (entry == NULL)
		{
			BND_STRG_DBGPRINT(DEBUG_WARN,
				"%s(): Index=%u, %02x:%02x:%02x:%02x:%02x:%02x, "
				"Entry not found.\n",
				__FUNCTION__, Index, PRINT_MAC(pAddr));
			//NdisReleaseSpinLock(&table->Lock);
			return BND_STRG_INVALID_ARG;
		}
	}
	else	
		entry = &table->Entry[Index];

	if (entry && entry->bValid) 
	{
#if 0
		/*if (MAC_ADDR_EQUAL(entry->Addr, pAddr))*/
#endif
		{
			pre_entry = NULL;
			this_entry = table->Hash[HashIdx];
			//ASSERT(this_entry);
			if (this_entry != NULL)
			{
				/* update Hash list*/
				do
				{
					if (this_entry == entry)
					{
						if (pre_entry == NULL)
							table->Hash[HashIdx] = entry->pNext;
						else
							pre_entry->pNext = entry->pNext;
						break;
					}

					pre_entry = this_entry;
					this_entry = this_entry->pNext;
				} while (this_entry);
			}

			/* not found !!!*/
			//ASSERT(this_entry != NULL);

			memset(entry->Addr, 0, MAC_ADDR_LEN);
			entry->tp.tv_sec = 0;
			entry->elapsed_time = 0;
			entry->bValid = FALSE;
			table->Size--;
		}
#if 0
		else {
			DBGPRINT(DEBUG_ERROR,
					("%s(): worng entry!\n", __FUNCTION__));
			ret_val = BND_STRG_UNEXP;
		}
#endif
	}
	//NdisReleaseSpinLock(&table->Lock);

	return ret_val;
}

/* We don't want to do too many things while handling Auth Req,
     so just let _BndStrg_AllowStaConnect2G() to check periodically.
     Hence, we only need to get the result in this function */
u8 bndstrg_allow_sta_conn_2g(struct bndstrg_cli_entry *entry)
{
	return ((entry) && (entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_2G));
}

u8 bndstrg_allow_sta_conn_5g(struct bndstrg_cli_entry *entry)
{
	return ((entry) && (entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G));
}


/* Check Probe/Auth Req to determine client's capability of 2.4g/5g */
int bndstrg_check_conn_req(
		struct bndstrg_cli_table *table,
		u8 			band,
		unsigned char *pSrcAddr,
		u8			FrameType,
		s8 			*rssi,
		u8 			bAllowStaConnectInHt)
{
	int 	ret_val = BND_STRG_SUCCESS;

	struct bndstrg_cli_entry *entry = NULL;
	struct bndstrg_entry_stat *statistics = NULL;

	DBGPRINT(DEBUG_TRACE, "\n");
	if (table->bInitialized == FALSE || table->bEnabled == FALSE)
		return BND_STRG_NOT_INITIALIZED;

	entry = bndstrg_table_lookup(table, pSrcAddr);

	if (entry == NULL)
	{
		ret_val = bndstrg_insert_entry(table, pSrcAddr, &entry);
	}

	if (entry)
	{
		s8 MaxRssi = rssi[0], i;

		for ( i = 1; i < 3; i++)
		{
			if (rssi[i])
				MaxRssi = max(MaxRssi, rssi[i]);	
		}

		if (band == BAND_2G)
		{
			entry->Control_Flags |= fBND_STRG_CLIENT_SUPPORT_2G;
			statistics = &entry->statistics[0];
		}
		else if (band == BAND_5G)
		{
			entry->Control_Flags |= fBND_STRG_CLIENT_SUPPORT_5G;
			statistics = &entry->statistics[1];
		}
		else
		{
			ret_val = BND_STRG_UNEXP;
		}

		if (statistics)
		{
			bndstrg_update_entry_statistics(statistics, MaxRssi, FrameType);
		}
		else
		{
			ret_val = BND_STRG_UNEXP;
		}

		if (statistics->Rssi != 0)
		{
			if (statistics->Rssi < (table->RssiLow))
			{
				entry->Control_Flags |= (band == BAND_2G) ? \
					fBND_STRG_CLIENT_LOW_RSSI_2G : fBND_STRG_CLIENT_LOW_RSSI_5G;
			} else {
				entry->Control_Flags &= (band == BAND_2G) ? \
					(~fBND_STRG_CLIENT_LOW_RSSI_2G) : (~fBND_STRG_CLIENT_LOW_RSSI_5G);
			}
		}

		if((bAllowStaConnectInHt == FALSE) && (FrameType == APMT2_PEER_PROBE_REQ))
		{
			if(band == BAND_2G) 
				entry->Control_Flags |= fBND_STRG_CLIENT_NOT_SUPPORT_HT_2G;

			if(band == BAND_5G)
				entry->Control_Flags |= fBND_STRG_CLIENT_NOT_SUPPORT_HT_5G;
		}

	}
	
	if (ret_val != BND_STRG_SUCCESS)
	{
		DBGPRINT(DEBUG_ERROR,
					"Error in %s(), error code = %d!\n", __FUNCTION__, ret_val);
	}

	return ret_val;
}


int bndstrg_event_test(struct bndstrg *bndstrg)
{

	DBGPRINT(DEBUG_OFF, "%s\n", __FUNCTION__);
	return 0;
}

int bndstrg_event_conn_req(struct bndstrg *bndstrg, struct bndstrg_msg *msg)
{
	DBGPRINT(DEBUG_TRACE,
			"%02x:%02x:%02x:%02x:%02x:%02x, Band = %u, frame_type = %u, rssi = %d/%d/%d/%d\n",
			PRINT_MAC(msg->Addr), msg->Band, msg->FrameType,
			msg->Rssi[0], msg->Rssi[1], msg->Rssi[2], msg->Rssi[3]);

	bndstrg_check_conn_req(&bndstrg->table,
							msg->Band,
							msg->Addr,
							msg->FrameType,
							msg->Rssi,
							msg->bAllowStaConnectInHt);
	
	return 0;
}

static int bndstrg_print_entry_statistics(struct bndstrg_entry_stat *statistics)
{
#ifdef BND_STRG_DBG
	BND_STRG_DBGPRINT(DEBUG_OFF,
						"Rssi = %4d, AuthReqCount = %3u\n",
						 statistics->Rssi, statistics->AuthReqCount);
#endif /* BND_STRG_DBG */
	return BND_STRG_SUCCESS;
}

static int bndstrg_print_ctrlflags(u32 flags)
{
#ifdef BND_STRG_DBG
	BND_STRG_DBGPRINT(DEBUG_OFF,
						"\t\tSupport_2G = %s\n"
						"\t\tSupport_5G = %s\n"
						"\t\tAllow to connect 2G = %s\n"
						"\t\tAllow to connect 5G = %s\n"
#if 0
						"\t\tHT Support 2G = %s\n"
						"\t\tHT Support 5G = %s\n"
#endif
						"\t\tLow Rssi 2G = %s\n"
						"\t\tLow Rssi 5G = %s\n"
						"\t\t2G Only = %s\n"
						"\t\t5G Only = %s\n",
						(flags & fBND_STRG_CLIENT_SUPPORT_2G) ? "yes" : "no",
						(flags & fBND_STRG_CLIENT_SUPPORT_5G) ? "yes" : "no",						
						(flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_2G) ? "yes" : "no",
						(flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G) ? "yes" : "no",
#if 0
						(flags & fBND_STRG_CLIENT_NOT_SUPPORT_HT_2G) ? "no" : "yes",
						(flags & fBND_STRG_CLIENT_NOT_SUPPORT_HT_5G) ? "no" : "yes",
#endif
						(flags & fBND_STRG_CLIENT_LOW_RSSI_2G) ? "yes" : "no",
						(flags & fBND_STRG_CLIENT_LOW_RSSI_5G) ? "yes" : "no",
						(flags & fBND_STRG_CLIENT_IS_2G_ONLY) ? "yes" : "no",
						(flags & fBND_STRG_CLIENT_IS_5G_ONLY) ? "yes" : "no");
#endif /* BND_STRG_DBG */
	return BND_STRG_SUCCESS;
}

static u32 bndstrg_get_entry_elapsed_time(struct bndstrg_cli_entry *entry)
{
	struct timespec now;
	u32 elapsed_time = 0;

	if (entry->tp.tv_sec) {
		get_current_system_tick(&now);
		elapsed_time = ((now.tv_sec - entry->tp.tv_sec)*1000) + \
						((now.tv_nsec - entry->tp.tv_nsec)/1000000);
	}

	return elapsed_time;
}

int bndstrg_print_entry(
			struct bndstrg_cli_table *table,
			struct bndstrg_cli_entry *entry)
{
#ifdef BND_STRG_DBG
	/* Update elapsed time */
	entry->elapsed_time = bndstrg_get_entry_elapsed_time(entry);

	if (entry->bValid)
	{
		if (MAC_ADDR_EQUAL(table->MonitorAddr, entry->Addr))
			BND_STRG_DBGPRINT(DEBUG_OFF, YLW("*"));

		BND_STRG_DBGPRINT(DEBUG_OFF,
			"\tbValid = %u, Index = %u, Control_Flags = 0x%08x,"
			  " Addr=%02x:%02x:%02x:%02x:%02x:%02x, elapsed time = %u (ms), aging = %u/%u\n",
				entry->bValid, entry->TableIndex, entry->Control_Flags,
				PRINT_MAC(entry->Addr), entry->elapsed_time,
				entry->AgingConfirmed[0], entry->AgingConfirmed[1]);
		BND_STRG_DBGPRINT(DEBUG_OFF,
			"\t\t2G:");
		bndstrg_print_entry_statistics(&entry->statistics[0]);
		BND_STRG_DBGPRINT(DEBUG_OFF,
			"\t\t5G:");
		bndstrg_print_entry_statistics(&entry->statistics[1]);

		if (MAC_ADDR_EQUAL(table->MonitorAddr, entry->Addr))
			bndstrg_print_ctrlflags(entry->Control_Flags);
	}
#endif /* BND_STRG_DBG */
	return BND_STRG_SUCCESS;
}

static int bndstrg_event_show_entries(struct bndstrg *bndstrg)
{
	int i;

	for (i = 0; i < BND_STRG_MAX_TABLE_SIZE; i++)
	{
		bndstrg_print_entry(&bndstrg->table, &bndstrg->table.Entry[i]);
	}

	return 0;
}

static int bndstrg_event_table_info(struct bndstrg *bndstrg)
{
	struct bndstrg_cli_table *table = &bndstrg->table;

	if (!table)
	{
		DBGPRINT(DEBUG_ERROR,
					"%s(): Error! table is NULL!\n", __FUNCTION__);
		return 0;
	}
	
	BND_STRG_DBGPRINT(DEBUG_OFF,
						"%s():\n"
							"\tbInitialized = %u\n"
							"\tbEnabled = %u\n"
							"\tb2GInfReady = %u\n"
							"\tb5GInfReady = %u\n"
							"\tRssiDiff = %d (dB)\n"
							"\tRssiLow = %d (dB)\n"
							"\tAgeTime = %u (ms)\n"
							"\tHoldTime = %u (ms)\n"
							"\tCheckTime_5G = %u (ms)\n"
							"\tFrameCheck = 0x%x\n"
							"\tConditionCheck = 0x%x\n"
#ifdef BND_STRG_DBG
							"\tMntAddr = %02x:%02x:%02x:%02x:%02x:%02x\n"
#endif /* BND_STRG_DBG */
							"\tSize = %u\n",
							__FUNCTION__,
							table->bInitialized,
							table->bEnabled,
							table->b2GInfReady,
							table->b5GInfReady,
							table->RssiDiff,
							table->RssiLow,
							table->AgeTime,
							table->HoldTime,
							table->CheckTime_5G,
							table->AlgCtrl.FrameCheck,
							table->AlgCtrl.ConditionCheck,
#ifdef BND_STRG_DBG
							PRINT_MAC(table->MonitorAddr),
#endif /* BND_STRG_DBG */
							table->Size);

	return 0;
}

static int bndstrg_event_on_off(struct bndstrg *bndstrg, u8 onoff, u8 band)
{
	BND_STRG_DBGPRINT(DEBUG_OFF, "onoff = %u,band = %u\n", onoff, band);
	DBGPRINT(DEBUG_ERROR,
			 "%s(): onoff = %u,band = %u\n", __func__, onoff, band);
	if (!onoff)
	{
		bndstrg->table.Band = bndstrg->table.Band & ~band;
		if ((band & BAND_2G) == BAND_2G) {
			bndstrg->table.b2GInfReady = FALSE;
			memset(bndstrg->table.uc2GIfName,0x00,sizeof(bndstrg->table.uc2GIfName));
		}
		if ((band & BAND_5G) == BAND_5G) {
			bndstrg->table.b5GInfReady = FALSE;
			memset(bndstrg->table.uc5GIfName,0x00,sizeof(bndstrg->table.uc5GIfName));
		}
	} else {
		bndstrg->table.Band = bndstrg->table.Band | band;
	}

	if (bndstrg->table.Band == (BAND_2G | BAND_5G)) {
		bndstrg->table.bEnabled = TRUE;
	}

	return 0;
}

int bndstrg_event_handle(struct bndstrg *bndstrg, char *data)
{
	struct bndstrg_msg msg;
	struct bndstrg_cli_table *table = &bndstrg->table;

	memcpy(&msg, data, sizeof(struct bndstrg_msg));

	switch (msg.Action)
	{
		case CONNECTION_REQ:
			bndstrg_event_conn_req(bndstrg, &msg);
			break;
			
		case INF_STATUS_RSP_2G:
			table->status_queried = 1;
			table->dbdc_mode = 0;
			table->b2GInfReady = msg.b2GInfReady;
			strcpy((char*)table->uc2GIfName,(char*)msg.uc2GIfName);
			break;
			
		case INF_STATUS_RSP_5G:
			table->status_queried = 1;
			table->dbdc_mode = 0;
			table->b5GInfReady = msg.b5GInfReady;
			strcpy((char*)table->uc5GIfName,(char*)msg.uc5GIfName);
			break;

		case INF_STATUS_RSP_DBDC:
			//TBD
			table->status_queried = 1;
			table->dbdc_mode = 1;
			table->b2GInfReady = msg.b2GInfReady;
			strcpy((char*)table->uc2GIfName,(char*)msg.uc2GIfName);
			table->b5GInfReady = msg.b5GInfReady;
			strcpy((char*)table->uc5GIfName,(char*)msg.uc5GIfName);
			break;

		case TABLE_INFO:
			bndstrg_event_table_info(bndstrg);
			break;
	
		case ENTRY_LIST:
			bndstrg_event_show_entries(bndstrg);
			break;

		case BNDSTRG_ONOFF:
			bndstrg_event_on_off(bndstrg, msg.OnOff, msg.Band);
			break;

		case CLI_AGING_RSP:
			BND_STRG_DBGPRINT(DEBUG_TRACE,
						"Got aging rsp. return code = %u,"
						"Addr = %02x:%02x:%02x:%02x:%02x:%02x\n",
						msg.ReturnCode, PRINT_MAC(msg.Addr));

			if (msg.ReturnCode == BND_STRG_SUCCESS)
			{
				struct bndstrg_cli_entry *entry = &table->Entry[msg.TalbeIndex];

				switch (msg.Band)
				{
					case BAND_2G:
						entry->AgingConfirmed[0] = 1;
						break;
					case BAND_5G:
						entry->AgingConfirmed[1] = 1;
						break;
					case (BAND_2G|BAND_5G):
						entry->AgingConfirmed[0] = 1;
						entry->AgingConfirmed[1] = 1;
						break;
					default:
						BND_STRG_DBGPRINT(DEBUG_ERROR,
						"Invalid Band (%u) from aging rsp\n", msg.Band);
						return BND_STRG_INVALID_ARG;
						break;
				}

				if (entry->AgingConfirmed[0] && entry->AgingConfirmed[1])
					bndstrg_delete_entry(table, msg.Addr, msg.TalbeIndex);
			}

			break;

		case CLI_DEL:
			bndstrg_delete_entry(table, msg.Addr, msg.TalbeIndex);
			break;

		case SET_RSSI_DIFF:
			table->RssiDiff = msg.RssiDiff;
			break;

		case SET_RSSI_LOW:
			table->RssiLow = msg.RssiLow;
			break;

		case SET_AGE_TIME:
			table->AgeTime = msg.Time;
			break;

		case SET_HOLD_TIME:
			table->HoldTime = msg.Time;
			break;

		case SET_CHECK_TIME:
			table->CheckTime_5G = msg.Time;
			break;

		case SET_CHEK_CONDITIONS:
			BND_STRG_DBGPRINT(DEBUG_OFF,
						"SET_CHEK_CONDITIONS\n");
			table->AlgCtrl.ConditionCheck = msg.ConditionCheck;
			break;
			
#ifdef BND_STRG_DBG
		case SET_MNT_ADDR:
			memcpy(table->MonitorAddr, msg.Addr, MAC_ADDR_LEN);
			break;
#endif

		default:
			BND_STRG_DBGPRINT(DEBUG_WARN,
						"Unkown event. (%u)\n",
						msg.Action);
			break;
	}
	
	return 0;
}


struct bndstrg_event_ops bndstrg_event_ops = {
	.event_handle = bndstrg_event_handle,
};

inline int bndstrg_accessible_cli(
				struct bndstrg *bndstrg,
				const char *iface,
				struct bndstrg_cli_entry *entry,
				u8 action)
{
	int ret = 0;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);
#if 0
	ret = bndstrg_drv_ops_pre_check(bndstrg, iface);

	if (ret) {
		DBGPRINT(DEBUG_ERROR, "%s: bndstrg drv ops pre check fail\n", __FUNCTION__);
		return -1;
	}
#endif
	ret = bndstrg->drv_ops->drv_accessible_cli(bndstrg->drv_data, iface, entry, action);

	return ret;
}

inline int bndstrg_inf_status_query(
				struct bndstrg *bndstrg,
				const char *iface)
{
	int ret = 0;

	DBGPRINT(DEBUG_TRACE, "\n");
#if 0
	ret = bndstrg_drv_ops_pre_check(bndstrg, iface);

	if (ret) {
		DBGPRINT(DEBUG_ERROR, "%s: bndstrg drv ops pre check fail\n", __FUNCTION__);
		return -1;
	}
#endif
	ret = bndstrg->drv_ops->drv_inf_status_query(bndstrg->drv_data, iface);

	return ret;
}

inline int bndstrg_onoff(
				struct bndstrg *bndstrg,
				const char *iface,
				u8 onoff)
{
	int ret = 0;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);
#if 0
	ret = bndstrg_drv_ops_pre_check(bndstrg, iface);

	if (ret) {
		DBGPRINT(DEBUG_ERROR, "%s: bndstrg drv ops pre check fail\n", __FUNCTION__);
		return -1;
	}
#endif
	ret = bndstrg->drv_ops->drv_bndstrg_onoff(bndstrg->drv_data, iface, onoff);

	return ret;
}


static u8 _bndstrg_allow_sta_conn_2g(
		struct bndstrg_cli_table *table,
		struct bndstrg_cli_entry *entry)
{
	struct bndstrg_entry_stat *statistics_2G = NULL, *statistics_5G = NULL;

	if (!table)
	{
		DBGPRINT(DEBUG_ERROR,
					"%s(): Error! table is NULL!\n", __FUNCTION__);
		return FALSE;
	}

	if (!entry)
	{
		DBGPRINT(DEBUG_ERROR,
			RED("%s(): Error! entry is NULL!\n"), __FUNCTION__);
		return FALSE;
	}

	if (IS_BND_STRG_DUAL_BAND_CLIENT(entry->Control_Flags))
	{
		statistics_2G = &entry->statistics[0];
		statistics_5G = &entry->statistics[1];
	
		/* Condition 1: 2G Rssi >> 5G Rssi */
		if ((table->AlgCtrl.ConditionCheck & fBND_STRG_CND_RSSI_DIFF) &&
			(statistics_2G->Rssi & statistics_5G->Rssi))
		{
			s8 RssiDiff = statistics_2G->Rssi - statistics_5G->Rssi;

			if (RssiDiff >= table->RssiDiff)
			{
#ifdef BND_STRG_QA
				BND_STRG_PRINTQAMSG(table, entry, 
				YLW("check RssiDiff >= %d, client (%02x:%02x:%02x:%02x:%02x:%02x)"
				" is allowed to connect 2.4G.\n"),
				table->RssiDiff, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
				return TRUE;
			}
		}

		/* Condition 2: Client really don't want to connect 5G */
		if ( (table->AlgCtrl.ConditionCheck & fBND_STRG_CND_2G_PERSIST) && 
			entry->elapsed_time >= table->HoldTime &&
			statistics_5G->AuthReqCount == 0 &&
			statistics_2G->AuthReqCount != 0)
		{
#ifdef BND_STRG_QA
			BND_STRG_PRINTQAMSG(table, entry,
			YLW("check elapsed_time >= %u (sec) and no auth req found in 5G,"
			" client (%02x:%02x:%02x:%02x:%02x:%02x) is allowed to connect 2.4G.\n"),
			table->HoldTime/1000, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
			return TRUE;
		}

		if ((table->AlgCtrl.ConditionCheck & fBND_STRG_CND_5G_RSSI) &&
		    (entry->Control_Flags & fBND_STRG_CLIENT_LOW_RSSI_5G) &&
		    !(entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G))
		{
#ifdef BND_STRG_QA
			BND_STRG_PRINTQAMSG(table, entry,
			YLW("check 5G Rssi(%d) < %d. client (%02x:%02x:%02x:%02x:%02x:%02x)"
			" is allowed to connect 2.4G.\n"),
			entry->statistics[1].Rssi, table->RssiLow, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
			return TRUE;
		}

		if ((table->AlgCtrl.ConditionCheck & fBND_STRG_CND_HT_SUPPORT) && 
		      (entry->Control_Flags & fBND_STRG_CLIENT_NOT_SUPPORT_HT_5G))
	{
#ifdef BND_STRG_QA
		BND_STRG_PRINTQAMSG(table, entry,
		YLW("check HT support: [legacy]. client (%02x:%02x:%02x:%02x:%02x:%02x)"
		" is allowed to connect 2.4G.\n"), PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
		return TRUE;
		}
	}

	if (entry->Control_Flags & fBND_STRG_CLIENT_IS_2G_ONLY)
	{
#ifdef BND_STRG_QA
		BND_STRG_PRINTQAMSG(table, entry,
		YLW("check 2.4G only. client (%02x:%02x:%02x:%02x:%02x:%02x)"
		" is allowed to connect 2.4G.\n"), PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
		return TRUE;
	}

	return FALSE;
}


static u8 _bndstrg_allow_sta_conn_5g(
		struct bndstrg_cli_table *table,
		struct bndstrg_cli_entry *entry)
{
	struct bndstrg_entry_stat *statistics_2G = NULL, *statistics_5G = NULL;
	if (!table)
	{
		DBGPRINT(DEBUG_ERROR,
					"%s(): Error! table is NULL!\n", __FUNCTION__);
		return FALSE;
	}

	if (!entry)
	{
		DBGPRINT(DEBUG_ERROR,
			RED("%s(): Error! entry is NULL!\n"), __FUNCTION__);
		return FALSE;
	}

	if (!(entry->Control_Flags & fBND_STRG_CLIENT_SUPPORT_5G))
		return FALSE;

	if (IS_BND_STRG_DUAL_BAND_CLIENT(entry->Control_Flags))
	{
		statistics_2G = &entry->statistics[0];
		statistics_5G = &entry->statistics[1];
		/* Condition 1: 2G Rssi >> 5G Rssi */
		if ((table->AlgCtrl.ConditionCheck & fBND_STRG_CND_RSSI_DIFF) &&
				(statistics_2G->Rssi & statistics_5G->Rssi))
		{
			s8 RssiDiff = statistics_2G->Rssi - statistics_5G->Rssi;
			if (RssiDiff >= table->RssiDiff)
			{	
#ifdef BND_STRG_QA
				BND_STRG_PRINTQAMSG(table, entry,
			      	RED("check RssiDiff >= %d, client (%02x:%02x:%02x:%02x:%02x:%02x)"
				" is not allowed to connect 5G.\n"),table->RssiDiff, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
				return FALSE;
			}
		}

		/* Condition 2: Client really don't want to connect 5G */
		if ( (table->AlgCtrl.ConditionCheck & fBND_STRG_CND_2G_PERSIST) && 
		   entry->elapsed_time >= table->HoldTime &&
		   statistics_5G->AuthReqCount == 0 &&
	   	   statistics_2G->AuthReqCount != 0)
		{
#ifdef BND_STRG_QA
			BND_STRG_PRINTQAMSG(table, entry,
			RED("check elapsed_time >= %u (sec) and no auth req found in 5G,"
			" client (%02x:%02x:%02x:%02x:%02x:%02x) is not allowed to connect 5G.\n"),
			table->HoldTime/1000, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
			return FALSE;
		}
											
		if ((table->AlgCtrl.ConditionCheck & fBND_STRG_CND_HT_SUPPORT) &&
		 (entry->Control_Flags & fBND_STRG_CLIENT_NOT_SUPPORT_HT_5G))
		{
#ifdef BND_STRG_QA
			if (entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G)
				BND_STRG_PRINTQAMSG(table, entry,
				RED("check 5G HT support. client (%02x:%02x:%02x:%02x:%02x:%02x)"
				" does not support HT.\n"), PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
			return FALSE;	
		}
	if ((table->AlgCtrl.ConditionCheck & fBND_STRG_CND_5G_RSSI) &&
		(entry->statistics[1].Rssi != 0))
	{
		if (entry->statistics[1].Rssi > table->RssiLow)
		//if (!(entry->Control_Flags & fBND_STRG_CLIENT_LOW_RSSI_5G))
		{
#ifdef BND_STRG_QA
			if (!(entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G))
			BND_STRG_PRINTQAMSG(table, entry,
			YLW("check 5G Rssi(%d) > %d. client (%02x:%02x:%02x:%02x:%02x:%02x)"
			" is allowed to connect 5G.\n"),
			entry->statistics[1].Rssi, table->RssiLow, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
#if 1 // TODO: move to 2.4G check
			entry->Control_Flags &=  (~fBND_STRG_CLIENT_ALLOW_TO_CONNET_2G);
			/* bndstrg_accessible_cli(bndstrg, IFNAME_2G, entry, CLI_DEL);*/
#endif
			return TRUE;
		}
		else if (entry->statistics[1].Rssi < (table->RssiLow - 10 /*Test*/))
		{
#ifdef BND_STRG_QA
			if (entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G)
			BND_STRG_PRINTQAMSG(table, entry,
			RED("check 5G Rssi(%d) < %d. client (%02x:%02x:%02x:%02x:%02x:%02x)"
			" is not allowed to connect 5G.\n"),
			entry->statistics[1].Rssi, (table->RssiLow -10), PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
			return FALSE;
		}
			else 
				return FALSE;
		}
		else if(entry->statistics[1].Rssi == 0)
		{
			DBGPRINT(DEBUG_ERROR,RED("%s(): Wrong RSSI value!\n"), __FUNCTION__);
			return FALSE;
		}
	}
	BND_STRG_PRINTQAMSG(table, entry,
	YLW("client (%02x:%02x:%02x:%02x:%02x:%02x)"
	" is allowed to connect 5G.\n"),PRINT_MAC(entry->Addr));
	return TRUE;
}


void bndstrg_periodic_exec(void *eloop_data, void *user_ctx)
{
	int i;
	u32 elapsed_time = 0;
	struct bndstrg_cli_entry *entry = NULL;
	struct bndstrg *bndstrg = (struct bndstrg*) user_ctx;
	struct bndstrg_cli_table *table = &bndstrg->table;

	if (!table)
	{
		DBGPRINT(DEBUG_ERROR,
					"%s(): Error! table is NULL!\n", __FUNCTION__);
		goto end_of_periodic_exec;
	}

	if (table->bInitialized == FALSE)
	{
		DBGPRINT(DEBUG_ERROR,
					"%s(): Error! table is not initialized!\n", __FUNCTION__);
		goto end_of_periodic_exec;
	}

	if ((table->status_queried_cnt >= 3) || (table->table_enable_cnt >= 3)) {
		DBGPRINT(DEBUG_OFF,
				 "%s(): Give up (2G ready=%d,5G ready=%d)(status query cnt=%d,enable cnt=%d), re-exec bndstrg again.\n", __FUNCTION__,table->b2GInfReady,table->b5GInfReady,table->status_queried_cnt,table->table_enable_cnt);
		eloop_terminate();
		return;
	}
	if (table->status_queried == 0) {//not query yet
		table->status_queried_cnt++;
		bndstrg_inf_status_query(bndstrg, IFNAME_2G);
		goto end_of_periodic_exec;
	} else if (table->b2GInfReady == FALSE) {
		table->status_queried_cnt++;
		bndstrg_inf_status_query(bndstrg, IFNAME_2G);
		goto end_of_periodic_exec;
	} else if (table->b5GInfReady == FALSE) {
		table->status_queried_cnt++;
		bndstrg_inf_status_query(bndstrg, IFNAME_5G);
		goto end_of_periodic_exec;
	} else if (table->bEnabled == FALSE) {
		/* If both 2G inf and 5G inf are ready, then tell driver to start running */
		table->table_enable_cnt++;
		DBGPRINT(DEBUG_OFF,
				 "%s(): table->dbdc_mode=%d,table->Band=%d\n", __FUNCTION__,table->dbdc_mode,table->Band);
		if (table->dbdc_mode == 1) {
			if ((table->Band & BAND_2G) != BAND_2G) {
				bndstrg_onoff(bndstrg, (char*)table->uc2GIfName, 1);
			}
			if ((table->Band & BAND_5G) != BAND_5G) {
				bndstrg_onoff(bndstrg, (char*)table->uc5GIfName, 1);
			}
		} else {
			if ((table->Band & BAND_2G) != BAND_2G) {
				bndstrg_onoff(bndstrg, (char*)IFNAME_2G, 1);
			}
			if ((table->Band & BAND_5G) != BAND_5G) {
				bndstrg_onoff(bndstrg, (char*)IFNAME_5G, 1);
			}
		}
		goto end_of_periodic_exec;
	}

	for (i = 0; i < BND_STRG_MAX_TABLE_SIZE; i++)
	{
		entry = &table->Entry[i];
		if (entry->bValid == TRUE)
		{
			elapsed_time = bndstrg_get_entry_elapsed_time(entry);
			if (elapsed_time >= table->AgeTime)
			{
				if (table->dbdc_mode == 1) {
					bndstrg_accessible_cli(bndstrg, table->uc2GIfName, entry, CLI_AGING_REQ);
					bndstrg_accessible_cli(bndstrg, table->uc5GIfName, entry, CLI_AGING_REQ);
				} else {
					bndstrg_accessible_cli(bndstrg, IFNAME_2G, entry, CLI_AGING_REQ);
					bndstrg_accessible_cli(bndstrg, IFNAME_5G, entry, CLI_AGING_REQ);
				}
				/*bndstrg_delete_entry(table, entry->Addr, i);*/
			}
			else
			{
				/* Update elapsed time */
				entry->elapsed_time = elapsed_time;

				if (elapsed_time >= table->CheckTime_5G &&
					!(entry->Control_Flags & fBND_STRG_CLIENT_SUPPORT_5G) &&
					!(entry->Control_Flags & fBND_STRG_CLIENT_IS_2G_ONLY))
				{
					/*	If we don't get any connection req from 5G for a long time,
						we condider this client is 2.4G only */
#ifdef BND_STRG_QA
					BND_STRG_PRINTQAMSG(table, entry,
					YLW("Receive no frame by 5G interface within %u seconds,"
					" set client (%02x:%02x:%02x:%02x:%02x:%02x) to 2.4G only.\n"),
					table->CheckTime_5G/1000, PRINT_MAC(entry->Addr));
#endif /* BND_STRG_QA */
					entry->Control_Flags |= \
						fBND_STRG_CLIENT_IS_2G_ONLY;
				}

				if (!(entry->Control_Flags & fBND_STRG_CLIENT_ALLOW_TO_CONNET_2G) &&
					_bndstrg_allow_sta_conn_2g(table, entry) == TRUE)
				{
					entry->Control_Flags |= \
						fBND_STRG_CLIENT_ALLOW_TO_CONNET_2G;
					/* tell driver this client can access 2G */
					if (table->dbdc_mode == 1) {
						bndstrg_accessible_cli(bndstrg, table->uc2GIfName, entry, CLI_ADD);
						bndstrg_accessible_cli(bndstrg, table->uc2GIfName, entry, CLI_UPDATE);
					} else {
						bndstrg_accessible_cli(bndstrg, IFNAME_2G, entry, CLI_ADD);
					}
				}

				if (!(entry->Control_Flags & fBND_STRG_CLIENT_IS_2G_ONLY))
				{
					if (_bndstrg_allow_sta_conn_5g(table, entry) == TRUE)
					{
						entry->Control_Flags |= \
							fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G;
						/* tell driver this client can access 5G */
						if (table->dbdc_mode == 1) {
							bndstrg_accessible_cli(bndstrg, table->uc5GIfName, entry, CLI_ADD);
							bndstrg_accessible_cli(bndstrg, table->uc5GIfName, entry, CLI_UPDATE);
						} else {
							bndstrg_accessible_cli(bndstrg, IFNAME_5G, entry, CLI_ADD);
						}
					} else {
						entry->Control_Flags &= \
							(~fBND_STRG_CLIENT_ALLOW_TO_CONNET_5G);
						/* tell driver this client cannot access 5G */
						// TODO: make sure access table entry exisit
						if (table->dbdc_mode == 1) {
							// only update entry control flag for dbdc mode
							bndstrg_accessible_cli(bndstrg, table->uc5GIfName, entry, CLI_UPDATE);
						} else {
							bndstrg_accessible_cli(bndstrg, IFNAME_5G, entry, CLI_DEL);
						}
					}
				}

			}
		}
	}

end_of_periodic_exec:

	eloop_register_timeout(1, 0, bndstrg_periodic_exec, NULL, bndstrg);

}

int bndstrg_table_init(struct bndstrg_cli_table *table)
{
	if (table->bInitialized == TRUE)
		return BND_STRG_SUCCESS;

	memset(table, 0, sizeof(struct bndstrg_cli_table));
	//OS_NdisAllocateSpinLock(&table->Lock);
	table->status_queried_cnt = 0;
	table->table_enable_cnt = 0;
	table->Band = 0;
	table->bEnabled = 0;
	table->RssiDiff= BND_STRG_RSSI_DIFF;
	table->RssiLow = BND_STRG_RSSI_LOW;
	table->AgeTime = BND_STRG_AGE_TIME;
	table->HoldTime = BND_STRG_HOLD_TIME;
	table->CheckTime_5G = BND_STRG_CHECK_TIME_5G;
	table->AlgCtrl.ConditionCheck = /*fBND_STRG_CND_RSSI_DIFF | \
								fBND_STRG_CND_2G_PERSIST | \
								fBND_STRG_CND_HT_SUPPORT | \ */
								fBND_STRG_CND_5G_RSSI;
	table->AlgCtrl.FrameCheck =  fBND_STRG_FRM_CHK_PRB_REQ | \
								fBND_STRG_FRM_CHK_ATH_REQ;
	table->bInitialized = TRUE;

	return BND_STRG_SUCCESS;
}

int bndstrg_init(struct bndstrg *bndstrg, 
				 struct bndstrg_event_ops *event_ops,
				 int drv_mode,
				 int opmode,
				 int version)
{
	int ret = 0;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);

	/* Initialze event loop */
	ret = eloop_init();
	
	if (ret)
	{	
		DBGPRINT(DEBUG_OFF, "eloop_register_timeout failed.\n");
		return -1;
	}

	/* use wireless extension */
	bndstrg->drv_ops = &bndstrg_drv_wext_ops;

	bndstrg->event_ops = event_ops;

	bndstrg->version = version;

	bndstrg->drv_data = bndstrg->drv_ops->drv_inf_init(bndstrg, opmode, drv_mode);

	ret = bndstrg_table_init(&bndstrg->table);

	if (ret == BND_STRG_SUCCESS)
		ret = eloop_register_timeout(1, 0, bndstrg_periodic_exec, NULL, bndstrg);

	return 0;
}

int bndstrg_deinit(struct bndstrg *bndstrg)
{
    int ret = 0;

    DBGPRINT(DEBUG_TRACE, "\n");

    ret = bndstrg->drv_ops->drv_inf_exit(bndstrg);

    if (ret)
        return -1;

    return 0;
}

static void bndstrg_terminate(int sig, void *signal_ctx)
{
	DBGPRINT(DEBUG_TRACE, "\n");
	
	eloop_terminate();
}

void bndstrg_run(struct bndstrg *bndstrg)
{
	struct bndstrg_cli_table *table = &bndstrg->table;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);
	
	eloop_register_signal_terminate(bndstrg_terminate, bndstrg);

	eloop_run();
	
	if (table->dbdc_mode == 1) {
		if ((table->Band & BAND_2G) == BAND_2G) {
			bndstrg_onoff(bndstrg, table->uc2GIfName, 0);
		}
		if ((table->Band & BAND_5G) != BAND_5G) {
			bndstrg_onoff(bndstrg, table->uc5GIfName, 0);
		}
	} else {
		if ((table->Band & BAND_2G) != BAND_2G) {
			bndstrg_onoff(bndstrg, IFNAME_2G, 0);
		}
		if ((table->Band & BAND_5G) != BAND_5G) {
			bndstrg_onoff(bndstrg, IFNAME_5G, 0);
		}
	}
}

