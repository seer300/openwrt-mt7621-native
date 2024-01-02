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
    	driver.h
*/

#ifndef __DRIVER_H__
#define __DRIVER_H__

#include "bndstrg.h"

struct bndstrg;
struct bndstrg_cli_entry;

struct bndstrg_drv_ops {
	int (*drv_test)(void *drv_data, const char *ifname);
	void * (*drv_inf_init)(struct bndstrg *bndstrg, const int opmode, const int drv_mode);
	int (*drv_inf_exit)(struct bndstrg *bndstrg);
	int (*drv_accessible_cli)(void *drv_data, const char *ifname, struct bndstrg_cli_entry *entry, u8 action);
	int (*drv_inf_status_query)(void *drv_data, const char *ifname);
	int (*drv_bndstrg_onoff)(void *drv_data, const char *ifname, u8 onoff);
};

#endif /* __DRIVER_H__ */
