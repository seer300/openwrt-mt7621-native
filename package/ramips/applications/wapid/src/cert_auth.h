
#ifndef __CERT_AUTH_H__
#define __CERT_AUTH_H__

#include "structure.h"
#include "cert_info.h"
#include "type_def.h"
#include "pack.h"
#include "debug.h"


//#define  FROM_MT_LEN 		1500
#define  FROM_MT_LEN 		5000		
#define  FROM_AS_LEN 		3000

int wai_initialize_ecdh(para_alg *ecdh);
int wai_copy_ecdh(para_alg *ecdh_a, para_alg *ecdh_b);
int wai_compare_ecdh(para_alg *ecdh_a, para_alg *ecdh_b);

int wai_fixdata_id_by_ident(void *cert_st, wai_fixdata_id *fixdata_id, UINT16 index);

#endif

