
#ifndef _X509_CERT_H
#define _X509_CERT_H

#define PEM_STRING_X509			"CERTIFICATE"
#define PEM_STRING_X509_ASU		"ASU CERTIFICATE"
#define PEM_STRING_X509_USER	"USER CERTIFICATE"
#define PEM_STRING_ECA			"EC PRIVATE KEY"
 
#define LOAD_CERT(TYPE, FILE_NAME, CERT_OBJ) \
static int	load_ ##TYPE(FILE_NAME, CERT_OBJ)

void X509_exit();
int X509_init();
tkey * x509_get_pubkey(X509 *x);
#endif

