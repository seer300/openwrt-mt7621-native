
#ifndef COMMON_H
#define COMMON_H

#define NIC_DBG_STRING      (" ")

#define RT_DEBUG_OFF		0
#define RT_DEBUG_ERROR		1
#define RT_DEBUG_WARN		2
#define RT_DEBUG_TRACE		3
#define RT_DEBUG_INFO		4

#define MAC_ADDR_LEN   		6
#define MAX_MBSSID_NUM		8
#define LEN_HEADER_802_3	14
#define NONCE_LEN			32

#define IN
#define OUT

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif // ETH_ALEN //

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif // IFNAMSIZ //

#ifndef NULL
#define NULL	0
#endif // NULL //

#define END_OF_ARGS		-1

#define NDIS_STATUS         			INT
#define NDIS_STATUS_SUCCESS             0x00
#define NDIS_STATUS_FAILURE             0x01
#define NDIS_STATUS_INVALID_DATA		0x02
#define NDIS_STATUS_RESOURCES           0x03

#define BIT(x) (1 << (x))

#if DBG
extern int 	RTDebugLevel;	

#define DBGPRINT(Level, fmt, args...)	\
{                                   	\
    if (Level <= RTDebugLevel)      	\
    {                               	\
        printf(NIC_DBG_STRING);   		\
		printf( fmt, ## args);			\
    }                               	\
}
#else
#define DBGPRINT(Level, fmt, args...) 	
#endif

typedef struct PACKED _ETHERNET_HEADER {
    UCHAR	Daddr[6];
    UCHAR 	Saddr[6];
    UCHAR 	Ethtype[2];
    UCHAR 	RcvdData[1];    
} ETHERNET_HEADER, *PETHERNET_HEADER;

struct os_time {
	os_time_t sec;
	os_time_t usec;
};

// 
// Helper macros definition
//
#define os_time_before(a, b) \
	((a)->sec < (b)->sec || \
	 ((a)->sec == (b)->sec && (a)->usec < (b)->usec))

#define os_time_sub(a, b, res) do { \
	(res)->sec = (a)->sec - (b)->sec; \
	(res)->usec = (a)->usec - (b)->usec; \
	if ((res)->usec < 0) { \
		(res)->sec--; \
		(res)->usec += 1000000; \
	} \
} while (0)

#undef  ASSERT
#define ASSERT(x)                                                               \
{                                                                               \
    if (!(x))                                                                   \
    {                                                                           \
        printf("ASSERT FAILED '" #x "' "	       								\
			       "%s %s:%d\n",			       								\
			       __FUNCTION__, __FILE__, __LINE__);      						\
    }                                                                           \
}

#define PRINT_MAC(addr)	\
	addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define NdisMoveMemory(Destination, Source, Length) memmove(Destination, Source, Length)
#define NdisZeroMemory(Destination, Length)         memset(Destination, 0, Length)
#define NdisFillMemory(Destination, Length, Fill)   memset(Destination, Fill, Length)
#define NdisEqualMemory(Source1, Source2, Length)   (!memcmp(Source1, Source2, Length))
#define RTMPEqualMemory(Source1, Source2, Length)	(!memcmp(Source1, Source2, Length))							

#define MAC_ADDR_EQUAL(pAddr1,pAddr2)           RTMPEqualMemory((PVOID)(pAddr1), (PVOID)(pAddr2), MAC_ADDR_LEN)

/**
 * os_get_time - Get current time (sec, usec)
 * @t: Pointer to buffer for the time
 * Returns: 0 on success, -1 on failure
 */
int os_get_time(struct os_time *t);
int os_get_random(unsigned char *buf, size_t len);
void hex_dump(char *str, unsigned char *pSrcBufVA, unsigned int SrcBufLen);
ULONG MakeOutgoingFrame(	OUT UCHAR *Buffer, OUT ULONG *FrameLen, ...);

#ifndef os_malloc
#define os_malloc(s) malloc((s))
#endif
#ifndef os_realloc
#define os_realloc(p, s) realloc((p), (s))
#endif
#ifndef os_free
#define os_free(p) free((p))
#endif

#ifndef os_memcpy
#define os_memcpy(d, s, n) memcpy((d), (s), (n))
#endif
#ifndef os_memmove
#define os_memmove(d, s, n) memmove((d), (s), (n))
#endif
#ifndef os_memset
#define os_memset(s, c, n) memset(s, c, n)
#endif
#ifndef os_memcmp
#define os_memcmp(s1, s2, n) memcmp((s1), (s2), (n))
#endif

#ifndef os_strdup
#ifdef _MSC_VER
#define os_strdup(s) _strdup(s)
#else
#define os_strdup(s) strdup(s)
#endif
#endif
#ifndef os_strlen
#define os_strlen(s) strlen(s)
#endif
#ifndef os_strcasecmp
#ifdef _MSC_VER
#define os_strcasecmp(s1, s2) _stricmp((s1), (s2))
#else
#define os_strcasecmp(s1, s2) strcasecmp((s1), (s2))
#endif
#endif
#ifndef os_strncasecmp
#ifdef _MSC_VER
#define os_strncasecmp(s1, s2, n) _strnicmp((s1), (s2), (n))
#else
#define os_strncasecmp(s1, s2, n) strncasecmp((s1), (s2), (n))
#endif
#endif
#ifndef os_strchr
#define os_strchr(s, c) strchr((s), (c))
#endif
#ifndef os_strcmp
#define os_strcmp(s1, s2) strcmp((s1), (s2))
#endif
#ifndef os_strncmp
#define os_strncmp(s1, s2, n) strncmp((s1), (s2), (n))
#endif
#ifndef os_strncpy
#define os_strncpy(d, s, n) strncpy((d), (s), (n))
#endif
#ifndef os_strrchr
#define os_strrchr(s, c) strrchr((s), (c))
#endif
#ifndef os_strstr
#define os_strstr(h, n) strstr((h), (n))
#endif

#ifndef os_snprintf
#ifdef _MSC_VER
#define os_snprintf _snprintf
#else
#define os_snprintf snprintf
#endif
#endif

#endif /* COMMON_H */


