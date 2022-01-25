#ifndef __ACRN_DEVICE_H__
#define __ACRN_DEVICE_H__

#include "domain_conf.h"

typedef struct _acrnMonitor acrnMonitor;
typedef acrnMonitor *acrnMonitorPtr;

typedef void (*acrnMonitorStopCallback)(virDomainObjPtr vm);
typedef struct _acrnMonitorMessage acrnMonitorMessage;
typedef acrnMonitorMessage *acrnMonitorMessagePtr;

struct _acrnMonitorMessage {
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

int acrnMonitorSystemPowerdown(acrnMonitorPtr mon);
acrnMonitorPtr acrnMonitorOpen(virDomainObjPtr vm, virDomainChrSourceDefPtr config, acrnMonitorStopCallback cb);
void acrnMonitorClose(acrnMonitorPtr mon);
bool acrnMonitorRegister(acrnMonitorPtr mon);
void acrnMonitorUnregister(acrnMonitorPtr mon);
int acrnMonitorGetReason(acrnMonitorPtr mon);
#endif /* __ACRN_DEVICE_H__ */
