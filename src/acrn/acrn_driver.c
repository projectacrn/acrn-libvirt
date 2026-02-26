/*
 * acrn_driver.c: core driver methods for managing acrn guests
 * Adapted from bhyve_driver.c. Original license and copyright:
 *
 * Copyright (C) 2014 Roman Bogorodskiy
 * Copyright (C) 2014-2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <fcntl.h>
#include <sys/utsname.h>

#include "virerror.h"
#include "datatypes.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "configmake.h"
#include "viralloc.h"
#include "network_conf.h"
#include "interface_conf.h"
#include "domain_audit.h"
#include "domain_event.h"
#include "snapshot_conf.h"
#include "virfdstream.h"
#include "storage_conf.h"
#include "node_device_conf.h"
#include "virdomainobjlist.h"
#include "virxml.h"
#include "virthread.h"
#include "virlog.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virtypedparam.h"
#include "virrandom.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "viraccessapicheck.h"
#include "virhostcpu.h"
#include "virhostmem.h"
#include "virhostdev.h"
#include "virportallocator.h"
#include "conf/domain_capabilities.h"
#include "virutil.h"
#include "domain_driver.h"

#include "acrn_conf.h"
#include "acrn_device.h"
#include "acrn_driver.h"
#include "acrn_command.h"
#include "acrn_parse_command.h"
#include "acrn_domain.h"
#include "acrn_process.h"
#include "acrn_capabilities.h"

#define VIR_FROM_THIS   VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_driver");

struct _acrnConn *acrn_driver = NULL;

static int
acrnAutostartDomain(virDomainObj *vm, void *opaque)
{
    const struct acrnAutostartData *data = opaque;
    int ret = 0;
    VIR_LOCK_GUARD lock = virObjectLockGuard(vm);

    if (vm->autostart && !virDomainObjIsActive(vm)) {
        virResetLastError();
        ret = virAcrnProcessStart(data->conn, vm,
                                   VIR_DOMAIN_RUNNING_BOOTED, 0);
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to autostart VM '%1$s': %2$s"),
                           vm->def->name, virGetLastErrorMessage());
        }
    }
    return ret;
}

static void
acrnAutostartDomains(struct _acrnConn *driver)
{
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen("acrn:///system");
    /* Ignoring NULL conn which is mostly harmless here */

    struct acrnAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains, false, acrnAutostartDomain, &data);

    virObjectUnref(conn);
}

/**
 * acrnDriverGetCapabilities:
 *
 * Get a reference to the virCaps *instance for the
 * driver.
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCaps *instance or NULL
 */
virCaps *ATTRIBUTE_NONNULL(1)
acrnDriverGetCapabilities(struct _acrnConn *driver)
{
    return virObjectRef(driver->caps);
}

static char *
acrnConnectGetCapabilities(virConnectPtr conn)
{
    struct _acrnConn *privconn = conn->privateData;
    g_autoptr(virCaps) caps = NULL;

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = acrnDriverGetCapabilities(privconn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to get Capabilities"));
        return NULL;
    }

    return virCapabilitiesFormatXML(caps);
}

static virDomainObj *
acrnDomObjFromDomain(virDomainPtr domain)
{
    virDomainObj *vm;
    struct _acrnConn *privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(privconn->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%1$s' (%2$s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}


static int
acrnConnectURIProbe(char **uri)
{
    if (acrn_driver == NULL)
        return 0;

    *uri = g_strdup("acrn:///system");
    return 1;
}


static virDrvOpenStatus
acrnConnectOpen(virConnectPtr conn,
                 virConnectAuthPtr auth G_GNUC_UNUSED,
                 virConf *conf G_GNUC_UNUSED,
                 unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected acrn URI path '%1$s', try acrn:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (acrn_driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("acrn state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    conn->privateData = acrn_driver;

    return VIR_DRV_OPEN_SUCCESS;
}

static int
acrnConnectClose(virConnectPtr conn)
{
    struct _acrnConn *privconn = conn->privateData;

    virCloseCallbacksDomainRunForConn(privconn->domains, conn);
    conn->privateData = NULL;

    return 0;
}

static char *
acrnConnectGetHostname(virConnectPtr conn)
{
    if (virConnectGetHostnameEnsureACL(conn) < 0)
        return NULL;

    return virGetHostname();
}

static char *
acrnConnectGetSysinfo(virConnectPtr conn, unsigned int flags)
{
    struct _acrnConn *privconn = conn->privateData;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCheckFlags(0, NULL);

    if (virConnectGetSysinfoEnsureACL(conn) < 0)
        return NULL;

    if (!privconn->hostsysinfo) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Host SMBIOS information is not available"));
        return NULL;
    }

    if (virSysinfoFormat(&buf, privconn->hostsysinfo) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

static int
acrnConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    unsigned long long tmpver;
    struct utsname ver;

    if (virConnectGetVersionEnsureACL(conn) < 0)
        return -1;

    uname(&ver);

    if (virStringParseVersion(&tmpver, ver.release, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown release: %1$s"), ver.release);
        return -1;
    }

    *version = tmpver;

    return 0;
}

static int
acrnDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetInfoEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        if (virAcrnGetDomainTotalCpuStats(vm, &(info->cpuTime)) < 0)
            goto cleanup;
    } else {
        info->cpuTime = 0;
    }

    info->state = virDomainObjGetState(vm, NULL);
    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainGetState(virDomainPtr domain,
                    int *state,
                    int *reason,
                    unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetStateEnsureACL(domain->conn, vm->def) < 0)
       goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    virDomainObj *vm;
    int ret = -1;

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    *autostart = vm->autostart;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainSetAutostart(virDomainPtr domain, int autostart)
{
    virDomainObj *vm;
    char *configFile = NULL;
    char *autostartLink = NULL;
    int ret = -1;

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainSetAutostartEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot set autostart for transient domain"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (vm->autostart != autostart) {
        if ((configFile = virDomainConfigFile(ACRN_CONFIG_DIR, vm->def->name)) == NULL)
            goto cleanup;
        if ((autostartLink = virDomainConfigFile(ACRN_AUTOSTART_DIR, vm->def->name)) == NULL)
            goto cleanup;

        if (autostart) {
            if (g_mkdir_with_parents(ACRN_AUTOSTART_DIR, 0777) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %1$s"),
                                     ACRN_AUTOSTART_DIR);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%1$s' to '%2$s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%1$s'"),
                                     autostartLink);
                goto cleanup;
            }
        }

        vm->autostart = autostart;
    }

    ret = 0;

 cleanup:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainIsActive(virDomainPtr domain)
{
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainIsActiveEnsureACL(domain->conn, obj->def) < 0)
        goto cleanup;

    ret = virDomainObjIsActive(obj);

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static int
acrnDomainIsPersistent(virDomainPtr domain)
{
    virDomainObj *obj;
    int ret = -1;

    if (!(obj = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainIsPersistentEnsureACL(domain->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->persistent;

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}

static char *
acrnDomainGetOSType(virDomainPtr dom)
{
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainGetOSTypeEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = g_strdup(virDomainOSTypeToString(vm->def->os.type));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
acrnDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    struct _acrnConn *privconn = domain->conn->privateData;
    virDomainObj *vm;
    char *ret = NULL;

    virCheckFlags(VIR_DOMAIN_XML_COMMON_FLAGS, NULL);

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainGetXMLDescEnsureACL(domain->conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainDefFormat(vm->def, privconn->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static virDomainPtr
acrnDomainDefineXMLFlags(virConnectPtr conn, const char *xml, unsigned int flags)
{
    struct _acrnConn *privconn = conn->privateData;
    virDomainPtr dom = NULL;
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virDomainDef) oldDef = NULL;
    virDomainObj *vm = NULL;
    virObjectEvent *event = NULL;
    g_autoptr(virCaps) caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    caps = acrnDriverGetCapabilities(privconn);
    if (!caps)
        return NULL;

    if ((def = virDomainDefParseString(xml, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virDomainDefineXMLFlagsEnsureACL(conn, def) < 0)
        goto cleanup;

    if (acrnDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, &def,
                                   privconn->xmlopt,
                                   0, &oldDef)))
        goto cleanup;
    vm->persistent = 1;

    if (virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                         privconn->xmlopt, ACRN_CONFIG_DIR) < 0) {
        virDomainObjListRemove(privconn->domains, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              !oldDef ?
                                              VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                              VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);

    return dom;
}

static virDomainPtr
acrnDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return acrnDomainDefineXMLFlags(conn, xml, 0);
}

static int
acrnDomainUndefineFlags(virDomainPtr domain, unsigned int flags)
{
    struct _acrnConn *privconn = domain->conn->privateData;
    virObjectEvent *event = NULL;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);
    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainUndefineFlagsEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(ACRN_CONFIG_DIR,
                              ACRN_AUTOSTART_DIR,
                              vm) < 0)
        goto cleanup;

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_UNDEFINED,
                                              VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm))
        vm->persistent = 0;
    else
        virDomainObjListRemove(privconn->domains, vm);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainUndefine(virDomainPtr domain)
{
    return acrnDomainUndefineFlags(domain, 0);
}

static int
acrnConnectListDomains(virConnectPtr conn, int *ids, int maxids)
{
    struct _acrnConn *privconn = conn->privateData;

    if (virConnectListDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListGetActiveIDs(privconn->domains, ids, maxids,
                                        virConnectListDomainsCheckACL, conn);
}

static int
acrnConnectNumOfDomains(virConnectPtr conn)
{
    struct _acrnConn *privconn = conn->privateData;

    if (virConnectNumOfDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(privconn->domains, true,
                                        virConnectNumOfDomainsCheckACL, conn);
}

static int
acrnConnectListDefinedDomains(virConnectPtr conn, char **const names,
                               int maxnames)
{
    struct _acrnConn *privconn = conn->privateData;

    if (virConnectListDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    memset(names, 0, sizeof(*names) * maxnames);
    return virDomainObjListGetInactiveNames(privconn->domains, names,
                                            maxnames,
                                            virConnectListDefinedDomainsCheckACL,
                                            conn);
}

static int
acrnConnectNumOfDefinedDomains(virConnectPtr conn)
{
    struct _acrnConn *privconn = conn->privateData;

    if (virConnectNumOfDefinedDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListNumOfDomains(privconn->domains, false,
                                        virConnectNumOfDefinedDomainsCheckACL,
                                        conn);
}

static char *
acrnConnectDomainXMLToNative(virConnectPtr conn,
                              const char *format,
                              const char *xmlData,
                              unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    struct _acrnConn *privconn = conn->privateData;
    g_autoptr(virDomainDef) def = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virCommand) loadcmd = NULL;

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLToNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(format, ACRN_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unsupported config type %1$s"), format);
        return NULL;
    }

    if (!(def = virDomainDefParseString(xmlData, privconn->xmlopt,
                                        NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        return NULL;

    if (acrnDomainAssignAddresses(def, NULL) < 0)
        return NULL;

    if (!(cmd = virAcrnProcessBuildAcrnCmd(privconn, def, true)))
        return NULL;

    virCommandToStringBuf(cmd, &buf, false, false);

    return virBufferContentAndReset(&buf);
}

static int
acrnConnectListAllDomains(virConnectPtr conn,
                           virDomainPtr **domains,
                           unsigned int flags)
{
    struct _acrnConn *privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    if (virConnectListAllDomainsEnsureACL(conn) < 0)
        return -1;

    return virDomainObjListExport(privconn->domains, conn, domains,
                                  virConnectListAllDomainsCheckACL, flags);
}

static virDomainPtr
acrnDomainLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid)
{
    struct _acrnConn *privconn = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(privconn->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching uuid '%1$s'"), uuidstr);
        goto cleanup;
    }

    if (virDomainLookupByUUIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr acrnDomainLookupByName(virConnectPtr conn,
                                            const char *name)
{
    struct _acrnConn *privconn = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(privconn->domains, name);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%1$s'"), name);
        goto cleanup;
    }

    if (virDomainLookupByNameEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static virDomainPtr
acrnDomainLookupByID(virConnectPtr conn,
                      int id)
{
    struct _acrnConn *privconn = conn->privateData;
    virDomainObj *vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByID(privconn->domains, id);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching ID '%1$d'"), id);
        goto cleanup;
    }

    if (virDomainLookupByIDEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
acrnDomainCreateWithFlags(virDomainPtr dom,
                           unsigned int flags)
{
    struct _acrnConn *privconn = dom->conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    unsigned int start_flags = 0;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY, -1);

    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_ACRN_PROCESS_START_AUTODESTROY;

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainCreateWithFlagsEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("Domain is already running"));
        goto cleanup;
    }

    ret = virAcrnProcessStart(dom->conn, vm,
                               VIR_DOMAIN_RUNNING_BOOTED,
                               start_flags);

    if (ret == 0)
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_STARTED,
                                                  VIR_DOMAIN_EVENT_STARTED_BOOTED);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainCreate(virDomainPtr dom)
{
    return acrnDomainCreateWithFlags(dom, 0);
}

static virDomainPtr
acrnDomainCreateXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    struct _acrnConn *privconn = conn->privateData;
    virDomainPtr dom = NULL;
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *vm = NULL;
    virObjectEvent *event = NULL;
    unsigned int start_flags = 0;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_AUTODESTROY |
                  VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;
    if (flags & VIR_DOMAIN_START_AUTODESTROY)
        start_flags |= VIR_ACRN_PROCESS_START_AUTODESTROY;

    if ((def = virDomainDefParseString(xml, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virDomainCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (acrnDomainAssignAddresses(def, NULL) < 0)
        goto cleanup;

    if (!(vm = virDomainObjListAdd(privconn->domains, &def,
                                   privconn->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE, NULL)))
        goto cleanup;

    if (virAcrnProcessStart(conn, vm,
                             VIR_DOMAIN_RUNNING_BOOTED,
                             start_flags) < 0) {
        /* If domain is not persistent, remove its data */
        if (!vm->persistent)
            virDomainObjListRemove(privconn->domains, vm);
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_BOOTED);

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);

    return dom;
}

static int
acrnDomainDestroyFlags(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn = dom->conn;
    struct _acrnConn *privconn = conn->privateData;
    virDomainObj *vm;
    virObjectEvent *event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainDestroyFlagsEnsureACL(conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    ret = virAcrnProcessStop(privconn, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (!vm->persistent)
        virDomainObjListRemove(privconn->domains, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainDestroy(virDomainPtr dom)
{
    return acrnDomainDestroyFlags(dom, 0);
}

static int
acrnDomainShutdownFlags(virDomainPtr dom, unsigned int flags)
{
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainShutdownFlagsEnsureACL(dom->conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    ret = virAcrnProcessShutdown(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainShutdown(virDomainPtr dom)
{
    return acrnDomainShutdownFlags(dom, 0);
}

static int
acrnDomainReboot(virDomainPtr dom, unsigned int flags)
{
    virConnectPtr conn = dom->conn;
    virDomainObj *vm;
    acrnDomainObjPrivate *priv;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_REBOOT_ACPI_POWER_BTN, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainRebootEnsureACL(conn, vm->def, flags) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    priv = vm->privateData;
    acrnMonitorSetReboot(priv->mon);

    ret = virAcrnProcessShutdown(vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainOpenConsole(virDomainPtr dom,
                       const char *dev_name,
                       virStreamPtr st,
                       unsigned int flags)
{
    virDomainObj *vm = NULL;
    virDomainChrDef *chr = NULL;
    acrnDomainObjPrivate *priv;
    int ret = -1;
    int dupfd = -1;
    ssize_t i = 0;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (virDomainOpenConsoleEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    if (virDomainObjCheckActive(vm) < 0)
        goto cleanup;

    priv = vm->privateData;
    if (dev_name) {
        for (i = 0; !chr && i < vm->def->nserials; i++) {
            if (STREQ(dev_name, vm->def->serials[i]->info.alias)) {
                chr = vm->def->serials[i];
                break;
            }
        }
    } else if (vm->def->nconsoles) {
        chr = vm->def->consoles[0];
        if (chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL)
            chr = vm->def->serials[0];
    }

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find character device %1$s"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %1$s is not using a PTY"),
                       dev_name ? dev_name : NULLSTR(chr->info.alias));
        goto cleanup;
    }

    if ((dupfd = dup(priv->ttyfds[i])) < 0) {
        virReportSystemError(errno, "%s", "dupfd");
        goto cleanup;
    }

    /* handle mutually exclusive access to console devices */
    ret = virFDStreamOpen(st, dupfd);
    if (ret < 0) {
        VIR_FORCE_CLOSE(dupfd);
        goto cleanup;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnDomainSetMetadata(virDomainPtr dom,
                       int type,
                       const char *metadata,
                       const char *key,
                       const char *uri,
                       unsigned int flags)
{
    virConnectPtr conn = dom->conn;
    struct _acrnConn *privconn = conn->privateData;
    virDomainObj *vm;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        return -1;

    if (virDomainSetMetadataEnsureACL(conn, vm->def, flags) < 0)
        goto cleanup;

    ret = virDomainObjSetMetadata(vm, type, metadata, key, uri,
                                  privconn->xmlopt, ACRN_STATE_DIR,
                                  ACRN_CONFIG_DIR, flags);

    if (ret == 0) {
        virObjectEvent *ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(vm, type, uri);
        virObjectEventStateQueue(privconn->domainEventState, ev);
    }


 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static char *
acrnDomainGetMetadata(virDomainPtr dom,
                      int type,
                      const char *uri,
                      unsigned int flags)
{
    virDomainObj *vm;
    char *ret = NULL;

    if (!(vm = acrnDomObjFromDomain(dom)))
        return NULL;

    if (virDomainGetMetadataEnsureACL(dom->conn, vm->def) < 0)
        goto cleanup;

    ret = virDomainObjGetMetadata(vm, type, uri, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnNodeGetCPUStats(virConnectPtr conn,
                     int cpuNum,
                     virNodeCPUStatsPtr params,
                     int *nparams,
                     unsigned int flags)
{
    if (virNodeGetCPUStatsEnsureACL(conn) < 0)
        return -1;

    return virHostCPUGetStats(cpuNum, params, nparams, flags);
}

static int
acrnNodeGetMemoryStats(virConnectPtr conn,
                        int cellNum,
                        virNodeMemoryStatsPtr params,
                        int *nparams,
                        unsigned int flags)
{
    if (virNodeGetMemoryStatsEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetStats(cellNum, params, nparams, flags);
}

static int
acrnNodeGetInfo(virConnectPtr conn,
                 virNodeInfoPtr nodeinfo)
{
    if (virNodeGetInfoEnsureACL(conn) < 0)
        return -1;

    return virCapabilitiesGetNodeInfo(nodeinfo);
}

static int
acrnStateCleanup(void)
{
    VIR_DEBUG("acrn state cleanup");

    if (acrn_driver == NULL)
        return -1;

    virObjectUnref(acrn_driver->hostdevMgr);
    virObjectUnref(acrn_driver->domains);
    virObjectUnref(acrn_driver->caps);
    virObjectUnref(acrn_driver->xmlopt);
    virSysinfoDefFree(acrn_driver->hostsysinfo);
    virObjectUnref(acrn_driver->domainEventState);
    virObjectUnref(acrn_driver->config);
    virPortAllocatorRangeFree(acrn_driver->remotePorts);

    if (acrn_driver->lockFD != -1)
        virPidFileRelease(ACRN_STATE_DIR, "driver", acrn_driver->lockFD);

    virMutexDestroy(&acrn_driver->lock);
    VIR_FREE(acrn_driver);

    return 0;
}

static int
acrnStateInitialize(bool privileged,
                     const char *root,
                     bool monolithic G_GNUC_UNUSED,
                     virStateInhibitCallback callback G_GNUC_UNUSED,
                     void *opaque G_GNUC_UNUSED)
{
    bool autostart = true;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return VIR_DRV_STATE_INIT_SKIPPED;
    }

    acrn_driver = g_new0(acrnConn, 1);

    acrn_driver->lockFD = -1;
    if (virMutexInit(&acrn_driver->lock) < 0) {
        VIR_FREE(acrn_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (!(acrn_driver->caps = virAcrnCapsBuild()))
        goto cleanup;

    if (virAcrnNodePrepare(acrn_driver) < 0)
        goto cleanup;

    if (virAcrnProbeCaps(&acrn_driver->acrncaps) < 0)
        goto cleanup;

    if (!(acrn_driver->xmlopt = virAcrnDriverCreateXMLConf(acrn_driver)))
        goto cleanup;

    if (!(acrn_driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(acrn_driver->domainEventState = virObjectEventStateNew()))
        goto cleanup;

    if (!(acrn_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto cleanup;

    if (!(acrn_driver->remotePorts = virPortAllocatorRangeNew(_("display"),
                                                               5900, 65535)))
        goto cleanup;

    acrn_driver->hostsysinfo = virSysinfoRead();

    if (!(acrn_driver->config = virAcrnDriverConfigNew()))
        goto cleanup;

    if (virAcrnLoadDriverConfig(acrn_driver->config, SYSCONFDIR "/libvirt/acrn.conf") < 0)
        goto cleanup;

    if (g_mkdir_with_parents(ACRN_LOG_DIR, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %1$s"),
                             ACRN_LOG_DIR);
        goto cleanup;
    }

    if (g_mkdir_with_parents(ACRN_STATE_DIR, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to mkdir %1$s"),
                             ACRN_STATE_DIR);
        goto cleanup;
    }

    if ((acrn_driver->lockFD =
         virPidFileAcquire(ACRN_STATE_DIR, "driver", getpid())) < 0)
        goto cleanup;

    if (virDomainObjListLoadAllConfigs(acrn_driver->domains,
                                       ACRN_STATE_DIR,
                                       NULL, true,
                                       acrn_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    if (virDomainObjListLoadAllConfigs(acrn_driver->domains,
                                       ACRN_CONFIG_DIR,
                                       ACRN_AUTOSTART_DIR, false,
                                       acrn_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    virAcrnProcessReconnectAll(acrn_driver);

    if (virDriverShouldAutostart(ACRN_STATE_DIR, &autostart) < 0)
        goto cleanup;

    if (autostart)
        acrnAutostartDomains(acrn_driver);

    return VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    acrnStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
}

unsigned
acrnDriverGetAcrnCaps(struct _acrnConn *driver)
{
    if (driver != NULL)
        return driver->acrncaps;
    return 0;
}

unsigned
acrnDriverGetGrubCaps(struct _acrnConn *driver)
{
    if (driver != NULL)
        return driver->grubcaps;
    return 0;
}

static int
acrnConnectGetMaxVcpus(virConnectPtr conn,
                        const char *type)
{
    if (virConnectGetMaxVcpusEnsureACL(conn) < 0)
        return -1;

    /*
     * Acrn supports up to 16 VCPUs, but offers no method to check this
     * value. Hardcode 16...
     */
    if (!type || STRCASEEQ(type, "acrn"))
        return 16;

    virReportError(VIR_ERR_INVALID_ARG, _("unknown type '%1$s'"), type);
    return -1;
}

static unsigned long long
acrnNodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long freeMem;

    if (virNodeGetFreeMemoryEnsureACL(conn) < 0)
        return 0;

    if (virHostMemGetInfo(NULL, &freeMem) < 0)
        return 0;

    return freeMem;
}

static int
acrnNodeGetCPUMap(virConnectPtr conn,
                   unsigned char **cpumap,
                   unsigned int *online,
                   unsigned int flags)
{
    if (virNodeGetCPUMapEnsureACL(conn) < 0)
        return -1;

    return virHostCPUGetMap(cpumap, online, flags);
}

static int
acrnNodeGetMemoryParameters(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int *nparams,
                             unsigned int flags)
{
    if (virNodeGetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemGetParameters(params, nparams, flags);
}

static int
acrnNodeSetMemoryParameters(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags)
{
    if (virNodeSetMemoryParametersEnsureACL(conn) < 0)
        return -1;

    return virHostMemSetParameters(params, nparams, flags);
}

static char *
acrnConnectBaselineCPU(virConnectPtr conn,
                        const char **xmlCPUs,
                        unsigned int ncpus,
                        unsigned int flags)
{
    virCPUDef **cpus = NULL;
    virCPUDef *cpu = NULL;
    char *cpustr = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (virConnectBaselineCPUEnsureACL(conn) < 0)
        goto cleanup;

    if (!(cpus = virCPUDefListParse(xmlCPUs, ncpus, VIR_CPU_TYPE_HOST)))
        goto cleanup;

    if (!(cpu = virCPUBaseline(VIR_ARCH_NONE, cpus, ncpus, NULL, NULL,
                               !!(flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE))))
        goto cleanup;

    if ((flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(cpus[0]->arch, cpu) < 0)
        goto cleanup;

    cpustr = virCPUDefFormat(cpu, NULL);

 cleanup:
    virCPUDefListFree(cpus);
    virCPUDefFree(cpu);

    return cpustr;
}

static int
acrnConnectCompareCPU(virConnectPtr conn,
                       const char *xmlDesc,
                       unsigned int flags)
{
    struct _acrnConn *driver = conn->privateData;
    g_autoptr(virCaps) caps = NULL;
    bool failIncompatible;
    bool validateXML;

    virCheckFlags(VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE |
                  VIR_CONNECT_COMPARE_CPU_VALIDATE_XML,
                  VIR_CPU_COMPARE_ERROR);

    if (virConnectCompareCPUEnsureACL(conn) < 0)
        return VIR_CPU_COMPARE_ERROR;

    failIncompatible = !!(flags & VIR_CONNECT_COMPARE_CPU_FAIL_INCOMPATIBLE);
    validateXML = !!(flags & VIR_CONNECT_COMPARE_CPU_VALIDATE_XML);

    if (!(caps = acrnDriverGetCapabilities(driver)))
        return VIR_CPU_COMPARE_ERROR;

    if (!caps->host.cpu ||
        !caps->host.cpu->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("cannot get host CPU capabilities"));
            return VIR_CPU_COMPARE_ERROR;
        }
        VIR_WARN("cannot get host CPU capabilities");
        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    return virCPUCompareXML(caps->host.arch, caps->host.cpu,
                            xmlDesc, failIncompatible, validateXML);
}

static int
acrnConnectDomainEventRegisterAny(virConnectPtr conn,
                                   virDomainPtr dom,
                                   int eventID,
                                   virConnectDomainEventGenericCallback callback,
                                   void *opaque,
                                   virFreeCallback freecb)
{
    struct _acrnConn *privconn = conn->privateData;
    int ret;

    if (virConnectDomainEventRegisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virDomainEventStateRegisterID(conn,
                                      privconn->domainEventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}

static int
acrnConnectDomainEventDeregisterAny(virConnectPtr conn,
                                     int callbackID)
{
    struct _acrnConn *privconn = conn->privateData;

    if (virConnectDomainEventDeregisterAnyEnsureACL(conn) < 0)
        return -1;

    if (virObjectEventStateDeregisterID(conn,
                                        privconn->domainEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}

static int
acrnDomainHasManagedSaveImage(virDomainPtr domain, unsigned int flags)
{
    virDomainObj *vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainHasManagedSaveImageEnsureACL(domain->conn, vm->def) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
acrnNodeDeviceDetachFlags(virNodeDevicePtr dev,
                           const char *driverName,
                           unsigned int flags)
{
    acrnConn *driver = dev->conn->privateData;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virCheckFlags(0, -1);

    if (!driverName)
        driverName = "acrn";

    if (STRNEQ(driverName, "acrn")) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported driver name '%1$s'"), driverName);
        return -1;
    }

    /* virNodeDeviceDetachFlagsEnsureACL() is being called by
     * virDomainDriverNodeDeviceDetachFlags() */
    return virDomainDriverNodeDeviceDetachFlags(dev, hostdev_mgr,
                                                VIR_PCI_STUB_DRIVER_VFIO, NULL);
}

static int
acrnNodeDeviceDettach(virNodeDevicePtr dev)
{
    return acrnNodeDeviceDetachFlags(dev, NULL, 0);
}

static int
acrnNodeDeviceReAttach(virNodeDevicePtr dev)
{
    acrnConn *driver = dev->conn->privateData;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    /* virNodeDeviceReAttachEnsureACL() is being called by
     * virDomainDriverNodeDeviceReAttach() */
    return virDomainDriverNodeDeviceReAttach(dev, hostdev_mgr);
}

static const char *
acrnConnectGetType(virConnectPtr conn)
{
    if (virConnectGetTypeEnsureACL(conn) < 0)
        return NULL;

    return "ACRN";
}

static int acrnConnectIsAlive(virConnectPtr conn G_GNUC_UNUSED)
{
    return 1;
}

static int
acrnConnectIsSecure(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}

static int
acrnConnectIsEncrypted(virConnectPtr conn G_GNUC_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}

static char *
acrnConnectDomainXMLFromNative(virConnectPtr conn,
                                const char *nativeFormat,
                                const char *nativeConfig,
                                unsigned int flags)
{
    g_autoptr(virDomainDef) def = NULL;
    struct _acrnConn *privconn = conn->privateData;
    unsigned acrnCaps = acrnDriverGetAcrnCaps(privconn);

    virCheckFlags(0, NULL);

    if (virConnectDomainXMLFromNativeEnsureACL(conn) < 0)
        return NULL;

    if (STRNEQ(nativeFormat, ACRN_CONFIG_FORMAT_ARGV)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %1$s"), nativeFormat);
        return NULL;
    }

    def = acrnParseCommandLineString(nativeConfig, acrnCaps,
                                      privconn->xmlopt);
    if (def == NULL)
        return NULL;

    return virDomainDefFormat(def, privconn->xmlopt, 0);
}

static char *
acrnConnectGetDomainCapabilities(virConnectPtr conn,
                                  const char *emulatorbin,
                                  const char *arch_str,
                                  const char *machine,
                                  const char *virttype_str,
                                  unsigned int flags)
{
    virDomainCaps *caps = NULL;
    char *ret = NULL;
    int virttype = VIR_DOMAIN_VIRT_ACRN;
    int arch = virArchFromHost(); /* virArch */

    virCheckFlags(0, ret);

    if (virConnectGetDomainCapabilitiesEnsureACL(conn) < 0)
        return ret;

    if (virttype_str &&
        (virttype = virDomainVirtTypeFromString(virttype_str)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %1$s"),
                       virttype_str);
        goto cleanup;
    }

    if (virttype != VIR_DOMAIN_VIRT_ACRN) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown virttype: %1$s"),
                       virttype_str);
        goto cleanup;
    }

    if (arch_str && (arch = virArchFromString(arch_str)) == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown architecture: %1$s"),
                       arch_str);
        goto cleanup;
    }

    if (!ARCH_IS_X86(arch)) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("unsupported architecture: %1$s"),
                       virArchToString(arch));
        goto cleanup;
    }

    if (emulatorbin == NULL)
        emulatorbin = "/usr/bin/acrn-dm";

    if (!(caps = virAcrnDomainCapsBuild(conn->privateData, emulatorbin,
                                         machine, arch, virttype)))
        goto cleanup;

    ret = virDomainCapsFormat(caps);

 cleanup:
    virObjectUnref(caps);
    return ret;
}

static virHypervisorDriver acrnHypervisorDriver = {
    .name = "acrn",
    .connectURIProbe = acrnConnectURIProbe,
    .connectOpen = acrnConnectOpen, /* 1.2.2 */
    .connectClose = acrnConnectClose, /* 1.2.2 */
    .connectGetVersion = acrnConnectGetVersion, /* 1.2.2 */
    .connectGetHostname = acrnConnectGetHostname, /* 1.2.2 */
    .connectGetSysinfo = acrnConnectGetSysinfo, /* 1.2.5 */
    .domainGetInfo = acrnDomainGetInfo, /* 1.2.2 */
    .domainGetState = acrnDomainGetState, /* 1.2.2 */
    .connectGetCapabilities = acrnConnectGetCapabilities, /* 1.2.2 */
    .connectListDomains = acrnConnectListDomains, /* 1.2.2 */
    .connectNumOfDomains = acrnConnectNumOfDomains, /* 1.2.2 */
    .connectListAllDomains = acrnConnectListAllDomains, /* 1.2.2 */
    .connectListDefinedDomains = acrnConnectListDefinedDomains, /* 1.2.2 */
    .connectNumOfDefinedDomains = acrnConnectNumOfDefinedDomains, /* 1.2.2 */
    .connectDomainXMLToNative = acrnConnectDomainXMLToNative, /* 1.2.5 */
    .domainCreate = acrnDomainCreate, /* 1.2.2 */
    .domainCreateWithFlags = acrnDomainCreateWithFlags, /* 1.2.3 */
    .domainCreateXML = acrnDomainCreateXML, /* 1.2.4 */
    .domainDestroy = acrnDomainDestroy, /* 1.2.2 */
    .domainDestroyFlags = acrnDomainDestroyFlags, /* 5.6.0 */
    .domainShutdown = acrnDomainShutdown, /* 1.3.3 */
    .domainShutdownFlags = acrnDomainShutdownFlags, /* 5.6.0 */
    .domainReboot = acrnDomainReboot, /* TBD */
    .domainLookupByUUID = acrnDomainLookupByUUID, /* 1.2.2 */
    .domainLookupByName = acrnDomainLookupByName, /* 1.2.2 */
    .domainLookupByID = acrnDomainLookupByID, /* 1.2.3 */
    .domainDefineXML = acrnDomainDefineXML, /* 1.2.2 */
    .domainDefineXMLFlags = acrnDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = acrnDomainUndefine, /* 1.2.2 */
    .domainUndefineFlags = acrnDomainUndefineFlags, /* 5.6.0 */
    .domainGetOSType = acrnDomainGetOSType, /* 1.2.21 */
    .domainGetXMLDesc = acrnDomainGetXMLDesc, /* 1.2.2 */
    .domainIsActive = acrnDomainIsActive, /* 1.2.2 */
    .domainIsPersistent = acrnDomainIsPersistent, /* 1.2.2 */
    .domainGetAutostart = acrnDomainGetAutostart, /* 1.2.4 */
    .domainSetAutostart = acrnDomainSetAutostart, /* 1.2.4 */
    .domainOpenConsole = acrnDomainOpenConsole, /* 1.2.4 */
    .domainSetMetadata = acrnDomainSetMetadata, /* 1.2.4 */
    .domainGetMetadata = acrnDomainGetMetadata, /* 1.2.4 */
    .nodeGetCPUStats = acrnNodeGetCPUStats, /* 1.2.2 */
    .nodeGetMemoryStats = acrnNodeGetMemoryStats, /* 1.2.2 */
    .nodeGetInfo = acrnNodeGetInfo, /* 1.2.3 */
    .connectGetMaxVcpus = acrnConnectGetMaxVcpus, /* 1.2.3 */
    .nodeGetFreeMemory = acrnNodeGetFreeMemory, /* 1.2.3 */
    .nodeGetCPUMap = acrnNodeGetCPUMap, /* 1.2.3 */
    .nodeGetMemoryParameters = acrnNodeGetMemoryParameters, /* 1.2.3 */
    .nodeSetMemoryParameters = acrnNodeSetMemoryParameters, /* 1.2.3 */
    .nodeDeviceDettach = acrnNodeDeviceDettach, /* 1.2.3 */
    .nodeDeviceDetachFlags = acrnNodeDeviceDetachFlags, /* 1.2.3 */
    .nodeDeviceReAttach = acrnNodeDeviceReAttach, /* 1.2.3 */
    .connectBaselineCPU = acrnConnectBaselineCPU, /* 1.2.4 */
    .connectCompareCPU = acrnConnectCompareCPU, /* 1.2.4 */
    .connectDomainEventRegisterAny = acrnConnectDomainEventRegisterAny, /* 1.2.5 */
    .connectDomainEventDeregisterAny = acrnConnectDomainEventDeregisterAny, /* 1.2.5 */
    .domainHasManagedSaveImage = acrnDomainHasManagedSaveImage, /* 1.2.13 */
    .connectGetType = acrnConnectGetType, /* 1.3.5 */
    .connectIsAlive = acrnConnectIsAlive, /* 1.3.5 */
    .connectIsSecure = acrnConnectIsSecure, /* 1.3.5 */
    .connectIsEncrypted = acrnConnectIsEncrypted, /* 1.3.5 */
    .connectDomainXMLFromNative = acrnConnectDomainXMLFromNative, /* 2.1.0 */
    .connectGetDomainCapabilities = acrnConnectGetDomainCapabilities, /* 2.1.0 */
};


static virConnectDriver acrnConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "acrn", NULL },
    .hypervisorDriver = &acrnHypervisorDriver,
};

static virStateDriver acrnStateDriver = {
    .name = "acrn",
    .stateInitialize = acrnStateInitialize,
    .stateCleanup = acrnStateCleanup,
};

int
acrnRegister(void)
{
    if (virRegisterConnectDriver(&acrnConnectDriver,
                                 true) < 0)
        return -1;
    if (virRegisterStateDriver(&acrnStateDriver) < 0)
        return -1;
    return 0;
}
