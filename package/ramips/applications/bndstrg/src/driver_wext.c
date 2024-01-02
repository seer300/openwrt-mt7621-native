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
    	driver_wext.c
*/

#include "bndstrg.h"
#include "driver_wext.h"
#include "priv_netlink.h"
#include "wireless_copy.h"
#include "netlink.h"
#include <sys/ioctl.h>


static void event_handle(struct driver_wext_data *drv_data, char *buf)
{
	struct bndstrg *bndstrg = (struct bndstrg *)drv_data->priv;

	bndstrg->event_ops->event_handle(bndstrg, buf);
}

static void driver_wext_event_wireless(struct driver_wext_data *drv,
                 void *ctx, char *data, int len)
{               
    struct iw_event iwe_buf, *iwe = &iwe_buf;
    char *pos, *end, *custom, *buf /*,*assoc_info_buf, *info_pos */;

    /* info_pos = NULL; */
	/* assoc_info_buf = NULL; */
    pos = data;
    end = data + len;   
    
    while (pos + IW_EV_LCP_LEN <= end) {
        /* 
 		 * Event data may be unaligned, so make a local, aligned copy
         * before processing. 
         */
        os_memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		
		DBGPRINT(DEBUG_INFO, "cmd = 0x%x len = %d\n", iwe->cmd, iwe->len);
        
		if (iwe->len <= IW_EV_LCP_LEN)
            return;

        custom = pos + IW_EV_POINT_LEN;

        //if (drv->we_version_compiled > 18 && iwe->cmd == IWEVCUSTOM) {
            /* WE-19 removed the pointer from struct iw_point */
            char *dpos = (char *) &iwe_buf.u.data.length;
            int dlen = dpos - (char *) &iwe_buf;
            os_memcpy(dpos, pos + IW_EV_LCP_LEN,
                  sizeof(struct iw_event) - dlen);
        //} else {
            //os_memcpy(&iwe_buf, pos, sizeof(struct iw_event));
            //custom += IW_EV_POINT_OFF;
		//}
		
		switch (iwe->cmd) {
        case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
               	return;
           	buf = os_malloc(iwe->u.data.length + 1);
            if (buf == NULL)
                return;
            os_memcpy(buf, custom, iwe->u.data.length);
            buf[iwe->u.data.length] = '\0';

            switch (iwe->u.data.flags) {
			case OID_BNDSTRG_MSG:
				event_handle(drv, buf); 
				break;

			default:
				DBGPRINT(DEBUG_ERROR, "unkwnon event type(%d)\n", iwe->u.data.flags);
				break; 
			}

           	os_free(buf);
            break;
        }

        pos += iwe->len;
    }
}

static int driver_wext_set_oid(struct driver_wext_data *drv_data, const char *ifname,
              				   unsigned short oid, char *data, size_t len)    
{
    char *buf;                             
    struct iwreq iwr;
	
    buf = os_zalloc(len);

    os_memset(&iwr, 0, sizeof(iwr));       
    os_strncpy(iwr.ifr_name, ifname, IFNAMSIZ);
    iwr.u.data.flags = oid;
    iwr.u.data.flags |= OID_GET_SET_TOGGLE;

    if (data)
        os_memcpy(buf, data, len);

	if (buf) {
    	iwr.u.data.pointer = (caddr_t)buf;    
    	iwr.u.data.length = len;
	} else {
    	iwr.u.data.pointer = NULL;    
    	iwr.u.data.length = 0;
	}

    if (ioctl(drv_data->ioctl_sock, RT_PRIV_IOCTL, &iwr) < 0) {
        DBGPRINT(DEBUG_ERROR, "%s: oid=0x%x len (%d) failed",
               __FUNCTION__, oid, len);
        os_free(buf);
        return -1;
    }

    os_free(buf);
    return 0;
}


/*
 * Test bndstrg cmd
 */
static int driver_wext_test(void *drv_data, const char *ifname)
{
	int ret;
	struct driver_wext_data *drv_wext_data = (struct driver_wext_data *)drv_data;	

	DBGPRINT(DEBUG_OFF, "%s\n", __FUNCTION__);

	ret = driver_wext_set_oid(drv_wext_data, ifname, OID_BNDSTRG_TEST, "123", 4);

	return ret;
}

static int driver_wext_accessible_cli(
				void *drv_data,
				const char *ifname,
				struct bndstrg_cli_entry *entry,
				u8 action)
{
	int ret;
	struct driver_wext_data *drv_wext_data = \
					(struct driver_wext_data *)drv_data;	
	struct bndstrg_msg msg;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);
	memcpy(msg.Addr, entry->Addr, MAC_ADDR_LEN);
	msg.TalbeIndex = entry->TableIndex;
	msg.Action = action;

	if (action == CLI_UPDATE) {
		msg.Control_Flags = entry->Control_Flags;
		msg.elapsed_time = entry->elapsed_time;
	}

	ret = driver_wext_set_oid(
				drv_wext_data,
				ifname,
				OID_BNDSTRG_MSG,
				(char *) &msg,
				sizeof(struct bndstrg_msg));

	return ret;
}

static int driver_wext_inf_status_query(
				void *drv_data,
				const char *ifname)
{
	int ret;
	struct driver_wext_data *drv_wext_data = \
					(struct driver_wext_data *)drv_data;	
	struct bndstrg_msg msg;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);
	msg.Action = INF_STATUS_QUERY;

	ret = driver_wext_set_oid(
				drv_wext_data,
				ifname,
				OID_BNDSTRG_MSG,
				(char *) &msg,
				sizeof(struct bndstrg_msg));
	DBGPRINT(DEBUG_TRACE, "ret = %u\n", ret);
	return ret;
}

static int driver_wext_bndstrg_onoff(
				void *drv_data,
				const char *ifname,
				u8 onoff)
{
	int ret;
	struct driver_wext_data *drv_wext_data = \
					(struct driver_wext_data *)drv_data;	
	struct bndstrg_msg msg;

	DBGPRINT(DEBUG_OFF, "%s\n", __FUNCTION__);
	msg.Action = BNDSTRG_ONOFF;
	msg.OnOff = onoff;

	ret = driver_wext_set_oid(
				drv_wext_data,
				ifname,
				OID_BNDSTRG_MSG,
				(char *) &msg,
				sizeof(struct bndstrg_msg));

	return ret;
}

static void driver_wext_event_rtm_newlink(void *ctx, struct ifinfomsg *ifi,
                    					  u8 *buf, size_t len)
{
    struct driver_wext_data *drv = ctx;
    int attrlen, rta_len;
    struct rtattr *attr;
    
    attrlen = len;

   	DBGPRINT(DEBUG_TRACE, "attrlen=%d", attrlen);

    attr = (struct rtattr *) buf;
    rta_len = RTA_ALIGN(sizeof(struct rtattr));
    while (RTA_OK(attr, attrlen)) {
        DBGPRINT(DEBUG_TRACE, "rta_type=%02x\n", attr->rta_type);
        if (attr->rta_type == IFLA_WIRELESS) {
            driver_wext_event_wireless(
                drv, ctx,
                ((char *) attr) + rta_len,
                attr->rta_len - rta_len);
        }
        attr = RTA_NEXT(attr, attrlen);
    }
}

static void *driver_wext_init(struct bndstrg *bndstrg, 
						      const int opmode,
							  const int drv_mode)
{
	struct driver_wext_data *drv_wext_data;
#if 1
	struct netlink_config *cfg;
#endif
	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);
	
	drv_wext_data = calloc(1, sizeof(*drv_wext_data));
	
	if (!drv_wext_data) {
		DBGPRINT(DEBUG_ERROR, "No avaliable memory for driver_wext_data\n");
		goto err1;

	}

	DBGPRINT(DEBUG_OFF, "Initialize ralink wext interface\n");

	drv_wext_data->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	
	if (drv_wext_data->ioctl_sock < 0) {
		DBGPRINT(DEBUG_ERROR, "socket(PF_INET,SOCK_DGRAM)");
		goto err2;
	}
#if 1
	cfg = os_zalloc(sizeof(*cfg));

    if (!cfg) {
		DBGPRINT(DEBUG_ERROR, "No avaliable memory for netlink cfg\n");
        goto err3;
    }

	cfg->ctx = drv_wext_data;
	cfg->newlink_cb = driver_wext_event_rtm_newlink;

	drv_wext_data->netlink = netlink_init(cfg);

	if (!drv_wext_data->netlink) {
		DBGPRINT(DEBUG_ERROR, "wext netlink init fail\n");
		goto err3;
	}
#endif

	drv_wext_data->priv = (void *)bndstrg;

	return (void *)drv_wext_data;

err3:
	close(drv_wext_data->ioctl_sock);
err2:
	os_free(drv_wext_data);
err1:
	return NULL;
}

static int driver_wext_exit(struct bndstrg *bndstrg)
{
	struct driver_wext_data *drv_wext_data = bndstrg->drv_data;

	DBGPRINT(DEBUG_TRACE, "%s\n", __FUNCTION__);

	netlink_deinit(drv_wext_data->netlink);

	close(drv_wext_data->ioctl_sock);
	
	os_free(drv_wext_data);

	return 0;
}

const struct bndstrg_drv_ops bndstrg_drv_wext_ops = {
	.drv_inf_init = driver_wext_init,
	.drv_inf_exit = driver_wext_exit,
	.drv_test = driver_wext_test,
	.drv_accessible_cli = driver_wext_accessible_cli,
	.drv_inf_status_query = driver_wext_inf_status_query,
	.drv_bndstrg_onoff = driver_wext_bndstrg_onoff,
};

