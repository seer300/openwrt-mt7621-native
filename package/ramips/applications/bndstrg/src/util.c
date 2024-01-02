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
    	util.c
*/

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "types.h"

#define BUF_SIZE 512

int  mtk_copy_file (const char *src, const char *dst)
{
    FILE *from, *to;
    char buf[BUF_SIZE];
    size_t size = 0;

    // Open
    if ((from = fopen (src, "rb")) == NULL) {
        printf ("can not open %s\n", src);
        return 1;
    }
    if ((to = fopen (dst, "wb")) ==  NULL) {
        return 2;
    }

    // Copy
    while ((size = fread (buf, 1, BUF_SIZE, from)) > 0) {
        fwrite (buf, 1, size, to);
    //    printf (".");
    }
    printf ("\n");

    // Close
    if (fclose (from) == EOF) {
        printf ("closing %s failed.\n", src);
        return 5;
    }
    if (fclose (to) == EOF) {
        printf ("closing %s failed.\n", dst);
        return 6;
    }

    return 0;
}

u8 BtoH(char ch)
{
    if (ch >= '0' && ch <= '9') return (ch - '0');        /* Handle numerals*/
    if (ch >= 'A' && ch <= 'F') return (ch - 'A' + 0xA);  /* Handle capitol hex digits*/
    if (ch >= 'a' && ch <= 'f') return (ch - 'a' + 0xA);  /* Handle small hex digits*/
    return(255);
}

void AtoH(char *src, char *dest, int destlen)
{
    char *srcptr;
    char *destTemp;

    srcptr = src;   
    destTemp = (char *) dest; 

    while(destlen--)
    {
        *destTemp = BtoH(*srcptr++) << 4;    /* Put 1st ascii byte in upper nibble.*/
        *destTemp += BtoH(*srcptr++);      /* Add 2nd ascii byte to above.*/
        destTemp++;
    }
}

void * __hide_aliasing_typecast(void *foo)         
{                                                                       
    return foo;        
}
