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
    	main.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#include "bndstrg.h"

extern struct bndstrg_event_ops bndstrg_event_ops;

int usage()
{

	DBGPRINT(DEBUG_OFF, "bndstrg  [-d <debug level>]\n");
	DBGPRINT(DEBUG_OFF, "-d <bndstrg debug level>\n");
	DBGPRINT(DEBUG_OFF, "-h help\n");
	return 0;
}

int process_options(int argc, char *argv[], char *filename,
					int *opmode, int *drv_mode, int *debug_level, int *version)
{
	int c;
	char *cvalue = NULL;
	
	opterr = 0;

	while ((c = getopt(argc, argv, "d:v:")) != -1) {
		switch (c) {
		case 'd':
			cvalue = optarg;
			if (os_strcmp(cvalue, "0") == 0)
				*debug_level = DEBUG_OFF;
			else if (os_strcmp(cvalue, "1") == 0)
				*debug_level = DEBUG_ERROR;
			else if (os_strcmp(cvalue, "2") == 0)
				*debug_level = DEBUG_WARN;
			else if (os_strcmp(cvalue, "3") == 0)
				*debug_level = DEBUG_TRACE;
			else if (os_strcmp(cvalue, "4") == 0)
				*debug_level = DEBUG_INFO;
			else {
				DBGPRINT(DEBUG_ERROR, "-d option does not have this debug_level %s\n", cvalue);
				return - 1;
			}
			break;
		case 'f':
			cvalue = optarg;
			os_strcpy(filename, cvalue);
			break;
		case 'v':
			cvalue = optarg;
			*version = atoi(cvalue);
 			break;
		case 'h':
			cvalue = optarg;
			usage();
			break;
		case '?':
			if (optopt == 'f') {
				DBGPRINT(DEBUG_OFF, "Option -%c requires an argument\n", optopt);
			} else if (optopt == 'd') {
				DBGPRINT(DEBUG_OFF, "Option -%c requires an argument\n", optopt);
			} else if (isprint(optopt)) {
				DBGPRINT(DEBUG_OFF, "Unknow options -%c\n", optopt);
			} else {

			}
			return -1;
			break;
		}
	}
	return 0;

}

int main(int argc, char *argv[])
{

	int ret;
	int opmode;
	int drv_mode;
	int debug_level;
	int version = 2;
	char filename[256] = {0}; 
	struct bndstrg bndstrg;
	pid_t child_pid;

	/* default setting */

	/* options processing */
	ret = process_options(argc, argv, filename, &opmode, &drv_mode, &debug_level, &version);

	if (ret) {
		usage();
		return -1;
	}

	DebugLevel = debug_level;
	
	child_pid = fork();

	if (child_pid == 0) {	
		DBGPRINT(DEBUG_OFF, "Initialize bndstrg\n");
		ret = bndstrg_init(&bndstrg, &bndstrg_event_ops, drv_mode, opmode, version);
	
		if (ret)
			goto error;

		bndstrg_run(&bndstrg);

	} else
		return 0;
#if 0
error0:
	bndstrg_deinit(&hs);
#endif
error:
	
	return ret;

}
