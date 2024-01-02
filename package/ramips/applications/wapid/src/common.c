
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#include "type_def.h"
#include "common.h"

extern int RTDebugLevel;

int os_get_time(struct os_time *t)
{
    int res;
    struct timeval tv;
    res = gettimeofday(&tv, NULL);
    t->sec = tv.tv_sec;
    t->usec = tv.tv_usec;
    return res;
}

int os_get_random(unsigned char *buf, size_t len)
{
    FILE *f;
    size_t rc;

    f = fopen("/dev/urandom", "rb");
    if (f == NULL)
    {
        printf("Could not open /dev/urandom.\n");
        return -1;
    }

    rc = fread(buf, 1, len, f);
    fclose(f);

    return rc != len ? -1 : 0;
}

void hex_dump(char *str, unsigned char *pSrcBufVA, unsigned int SrcBufLen)
{
    unsigned char *pt;
    int x;

    if (RTDebugLevel < RT_DEBUG_TRACE)
        return;

    pt = pSrcBufVA;
    printf("%s: Len(%d)\n", str, SrcBufLen);
    for (x = 0; x < SrcBufLen; x++)
    {
        if (x % 16 == 0)
            printf("0x%04x : ", x);
        printf("%02x ", ((unsigned char)pt[x]));
        if (x%16 == 15) printf("\n");
    }
    printf("\n");
}


/*
  ***************************************************************************
  This routine build an outgoing frame, and fill all information specified
  in argument list to the frame body. The actual frame size is the summation
  of all arguments.
  input params:
        Buffer - pointer to a pre-allocated memory segment
        args - a list of <int arg_size, arg> pairs.
        NOTE NOTE NOTE!!!! the last argument must be NULL, otherwise this
                           function will FAIL!!!
  return:
        Size of the buffer
  usage:
        MakeOutgoingFrame(Buffer, output_length, 2, &fc, 2, &dur, 6, p_addr1, 6,p_addr2, END_OF_ARGS);


  ***************************************************************************
 */
ULONG MakeOutgoingFrame(
    OUT UCHAR *Buffer,
    OUT ULONG *FrameLen, ...)
{
    CHAR   *p;
    int     leng;
    ULONG   TotLeng;
    va_list Args;

    // calculates the total length
    TotLeng = 0;
    va_start(Args, FrameLen);
    do
    {
        leng = va_arg(Args, int);
        if (leng == END_OF_ARGS)
        {
            break;
        }
        p = va_arg(Args, PVOID);
        os_memmove(&Buffer[TotLeng], p, leng);
        TotLeng = TotLeng + leng;
    }
    while(TRUE);

    va_end(Args); /* clean up */
    *FrameLen = TotLeng;
    return TotLeng;
}


