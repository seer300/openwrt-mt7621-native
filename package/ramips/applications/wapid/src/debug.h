
#ifndef __DEBUG_H__
#define __DEBUG_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int debug;
#define DPrintf if (!debug) ; else printf
//#define DPrint_string if(!debug); else print_string
#define DPrint_string print_string
#define DPrint_to_string if(!debug); else print_to_string
#define DPrint_hex_string if(!debug); else print_hex_string
#define DPrint_string_array if(!debug); else print_string_array
#define DPrint_EC_KEY	if(!debug); else EC_KEY_print_fp_my
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

void PrintBuffer(const void* start, int offset);
char* SPrintBuffer(const void *start, int offset, int len );
void print_hex_string(void *_buf, int len);
void print_to_string(char* buf, int len);
void print_string(void *str,int len);
void print_string_array(char *name, void *_str,int len);

#endif //  #ifndef _MY_TRACEFUNC_H__

