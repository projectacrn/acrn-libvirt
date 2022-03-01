#ifndef __ACRN_DOMAIN_H__
#define __ACRN_DOMAIN_H__

#include "domain_conf.h"
#include "acrn_monitor.h"

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

    virDomainChrSourceDefPtr monConfig;
    char *libDir;            /* base path for per-domain files */
    acrnMonitorPtr mon;
};

typedef struct _acrnDomainXmlNsDef acrnDomainXmlNsDef;
typedef acrnDomainXmlNsDef *acrnDomainXmlNsDefPtr;
struct _acrnDomainXmlNsDef {
    bool rtvm;
    size_t nargs;
    char **args;
};

void acrnDomainTtyCleanup(acrnDomainObjPrivatePtr priv);
virDomainXMLOptionPtr virAcrnDriverCreateXMLConf(void);
#endif /* __ACRN_DOMAIN_H__ */
