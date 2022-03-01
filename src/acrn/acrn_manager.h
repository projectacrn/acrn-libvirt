#ifndef __ACRN_MANAGER_H__
#define __ACRN_MANAGER_H__

#include "domain_conf.h"

typedef struct _acrnManager acrnManager;
typedef acrnManager *acrnManagerPtr;

typedef void (*acrnManagerStopCallback)(virDomainObjPtr vm);
typedef struct _acrnManagerMessage acrnManagerMessage;
typedef acrnManagerMessage *acrnManagerMessagePtr;

struct _acrnManagerMessage {
    int txFD;

    char *txBuffer;
    int txOffset;
    int txLength;

    /* Used by the text monitor reply / error */
    char *rxBuffer;
    int rxLength;
    /* Used by the JSON monitor to hold reply / error */
    void *rxObject;

    /* True if rxBuffer / rxObject are ready, or a
     * fatal error occurred on the monitor channel
     */
    bool finished;
};

int acrnManagerSystemPowerdown(acrnManagerPtr mon);
int acrnManagerSystemReboot(acrnManagerPtr mon);
acrnManagerPtr acrnManagerOpen(virDomainObjPtr vm, virDomainChrSourceDefPtr config, acrnManagerStopCallback cb);
void acrnManagerClose(acrnManagerPtr mon);
bool acrnManagerRegister(acrnManagerPtr mon);
void acrnManagerUnregister(acrnManagerPtr mon);
int acrnManagerGetReason(acrnManagerPtr mon);
#endif /* __ACRN_MANAGER_H__ */
