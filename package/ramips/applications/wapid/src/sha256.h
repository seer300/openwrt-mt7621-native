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
	sha256.h
	
	Revision History:
	Who 			When			What
	--------		----------		----------------------------------------------
	Albert Yang		2008/4/10		SHA256 definition
	
*/

#include "type_def.h"

#define SHA256_MAC_LEN 32

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

void sha256_vector(
	size_t num_elem, 
	const unsigned char *addr[], 
	const size_t *len,
	unsigned char *mac);

void hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *data,
		 size_t data_len, unsigned char *mac);

void kd_hmac_sha256(	
    unsigned char 	*key, 
    unsigned int 	key_len,
    unsigned char 	*text, 
	unsigned int 	text_len,
    unsigned char 	*output, 
    unsigned int 	output_len);

