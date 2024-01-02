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
    	util.h
*/

#ifndef __UTIL_H__
#define __UTIL_H__

u8 BtoH(char ch);
void AtoH(char *src, char *dest, int destlen);

/* Endian byte swapping codes */
#define SWAP16(x) \
    ((u16) (\
           (((u16) (x) & (u16) 0x00ffU) << 8) | \
           (((u16) (x) & (u16) 0xff00U) >> 8))) 
 
#define SWAP32(x) \
    ((u32) (\
           (((u32) (x) & (u32) 0x000000ffUL) << 24) | \
           (((u32) (x) & (u32) 0x0000ff00UL) << 8) | \
           (((u32) (x) & (u32) 0x00ff0000UL) >> 8) | \
           (((u32) (x) & (u32) 0xff000000UL) >> 24))) 

#define SWAP64(x) \
    ((u64)( \
    (u64)(((UINT64)(x) & (u64) 0x00000000000000ffULL) << 56) | \
    (u64)(((UINT64)(x) & (u64) 0x000000000000ff00ULL) << 40) | \
    (u64)(((UINT64)(x) & (u64) 0x0000000000ff0000ULL) << 24) | \
    (u64)(((UINT64)(x) & (u64) 0x00000000ff000000ULL) <<  8) | \
    (u64)(((UINT64)(x) & (u64) 0x000000ff00000000ULL) >>  8) | \
    (u64)(((UINT64)(x) & (u64) 0x0000ff0000000000ULL) >> 24) | \
    (u64)(((UINT64)(x) & (u64) 0x00ff000000000000ULL) >> 40) | \
    (u64)(((UINT64)(x) & (u64) 0xff00000000000000ULL) >> 56) ))
 
#ifdef RT_BIG_ENDIAN
#define cpu2le64(x) SWAP64((x))
#define le2cpu64(x) SWAP64((x))
#define cpu2le32(x) SWAP32((x))
#define le2cpu32(x) SWAP32((x))
#define cpu2le16(x) SWAP16((x))
#define le2cpu16(x) SWAP16((x))
#define cpu2be64(x) ((u64)(x))
#define be2cpu64(x) ((u64)(x))
#define cpu2be32(x) ((u32)(x))
#define be2cpu32(x) ((u32)(x))
#define cpu2be16(x) ((u16)(x))
#define be2cpu16(x) ((u16)(x))
#else /* Little_Endian */
#define cpu2le64(x) ((u64)(x))
#define le2cpu64(x) ((u64)(x))
#define cpu2le32(x) ((u32)(x))
#define le2cpu32(x) ((u32)(x))
#define cpu2le16(x) ((u16)(x))
#define le2cpu16(x) ((u16)(x))
#define cpu2be64(x) SWAP64((x))
#define be2cpu64(x) SWAP64((x))
#define cpu2be32(x) SWAP32((x))
#define be2cpu32(x) SWAP32((x))
#define cpu2be16(x) SWAP16((x))
#define be2cpu16(x) SWAP16((x))
#endif /* RT_BIG_ENDIAN */

void * __hide_aliasing_typecast(void *foo);
#define aliasing_hide_typecast(a,t) (t *) __hide_aliasing_typecast((a))

#define max(_a, _b)     (((_a) > (_b)) ? (_a) : (_b))
#define MAC_ADDR_HASH(Addr)            (Addr[0] ^ Addr[1] ^ Addr[2] ^ Addr[3] ^ Addr[4] ^ Addr[5])
#define MAC_ADDR_HASH_INDEX(Addr)      (MAC_ADDR_HASH(Addr) & (HASH_TABLE_SIZE - 1))
#define MAC_ADDR_EQUAL(pAddr1,pAddr2)           !memcmp((void *)(pAddr1), (void *)(pAddr2), MAC_ADDR_LEN)
#define PRINT_MAC(addr)	addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
#endif /* __UTIL_H__ */
