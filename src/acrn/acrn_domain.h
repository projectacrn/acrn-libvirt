#ifndef __ACRN_DOMAIN_H__
#define __ACRN_DOMAIN_H__

#include "domain_conf.h"

typedef struct _acrnDomainObjPrivate acrnDomainObjPrivate;
typedef acrnDomainObjPrivate *acrnDomainObjPrivatePtr;
struct _acrnDomainObjPrivate {
    unsigned char hvUUID[VIR_UUID_BUFLEN];
    virBitmapPtr cpuAffinitySet;
    struct {
        int fd;
        char *slave;
    } ttys[4];
    size_t nttys;
};

void acrnDomainTtyCleanup(acrnDomainObjPrivatePtr priv);
virDomainXMLOptionPtr virAcrnDriverCreateXMLConf(void);
#endif /* __ACRN_DOMAIN_H__ */
