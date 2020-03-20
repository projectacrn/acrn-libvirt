#include <config.h>
#include <fcntl.h>
#include <libxml/xpathInternals.h>
#include "datatypes.h"
#include "virdomainobjlist.h"
#include "virerror.h"
#include "viralloc.h"
#include "cpu/cpu.h"
#include "vircommand.h"
#include "virthread.h"
#include "virstring.h"
#include "virlog.h"
#include "acrn_driver.h"
#include "acrn_domain.h"

#define VIR_FROM_THIS VIR_FROM_ACRN
#define ACRN_DM_PATH "/usr/bin/acrn-dm"
#define ACRN_CTL_PATH "/usr/bin/acrnctl"
#define ACRN_NAMESPACE_HREF "http://libvirt.org/schemas/domain/acrn/0.0"
#define ACRN_OFFLINE_PATH "/sys/class/vhm/acrn_vhm/offline_cpu"
#define SYSFS_CPU_PATH "/sys/devices/system/cpu"

VIR_LOG_INIT("acrn.acrn_driver");

typedef struct _acrnConnect acrnConnect;
typedef struct _acrnConnect *acrnConnectPtr;
struct _acrnConnect {
    virMutex lock;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virDomainObjListPtr domains;
};

typedef struct _acrnDomainNamespaceDef acrnDomainNamespaceDef;
typedef acrnDomainNamespaceDef *acrnDomainNamespaceDefPtr;
struct _acrnDomainNamespaceDef {
    size_t num_args;
    char **args;
};

static acrnConnectPtr acrn_driver = NULL;

/**
 * Get a reference to the virCapsPtr instance for the
 * driver.
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCapsPtr instance or NULL
 */
static virCapsPtr ATTRIBUTE_NONNULL(1)
acrnDriverGetCapabilities(acrnConnectPtr driver)
{
    return virObjectRef(driver->caps);
}

static virDomainObjPtr
acrnDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    acrnConnectPtr privconn = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUID(privconn->domains, domain->uuid);

    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
        return NULL;
    }

    return vm;
}

static virCommandPtr
acrnBuildStopCmd(virDomainDefPtr def)
{
    virCommandPtr cmd;

    if (!def)
        return NULL;

    if (!(cmd = virCommandNew(ACRN_CTL_PATH))) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    virCommandAddArgList(cmd, "stop", "-f", NULL);
    virCommandAddArg(cmd, def->name);
    return cmd;
}

static int
acrnProcessStop(virDomainObjPtr vm, int reason)
{
    virCommandPtr cmd;
    int ret = -1;

    if (!(cmd = acrnBuildStopCmd(vm->def)))
        goto cleanup;

    VIR_DEBUG("Stopping domain '%s'", vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    ret = 0;

cleanup:
    virCommandFree(cmd);
    return ret;
}

static int
acrnDomainShutdown(virDomainPtr dom)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (acrnProcessStop(vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
acrnDomainDestroy(virDomainPtr dom)
{
    acrnConnectPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainState state;
    int reason, ret = -1;

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    state = virDomainObjGetState(vm, &reason);

    if (state == VIR_DOMAIN_SHUTOFF) {
        if (reason != VIR_DOMAIN_SHUTOFF_DESTROYED)
            virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_DESTROYED);
    } else {
        if (acrnProcessStop(vm, VIR_DOMAIN_SHUTOFF_DESTROYED) < 0)
            goto cleanup;
    }

    if (!vm->persistent &&
        (state != VIR_DOMAIN_SHUTOFF ||
         reason != VIR_DOMAIN_SHUTOFF_DESTROYED)) {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
    }

    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static virDomainPtr
acrnDomainLookupByName(virConnectPtr conn, const char *name)
{
    acrnConnectPtr privconn = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByName(privconn->domains, name);

    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%s'"), name);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

 cleanup:
    virDomainObjEndAPI(&vm);
    return dom;
}

static int
acrnDomainGetInfo(virDomainPtr dom, virDomainInfoPtr info)
{
    virDomainObjPtr vm;
    int ret = -1;

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    info->state = virDomainObjGetState(vm, NULL);
    info->maxMem = virDomainDefGetMemoryTotal(vm->def);
    info->nrVirtCpu = virDomainDefGetVcpus(vm->def);
    ret = 0;

 cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
acrnConnectListAllDomains(virConnectPtr conn,
                          virDomainPtr **domains,
                          unsigned int flags)
{
    acrnConnectPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    return virDomainObjListExport(privconn->domains, conn, domains, NULL,
                                  flags);
}

static int
acrnProcessPrepareDomain(virConnectPtr conn ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm)
{
    virDomainDefPtr def = NULL;
    virBitmapPtr map = NULL;
    char path[128], chr, online = 'x';
    int fd, i, ret = -1;
    ssize_t rc;

    if (!(def = vm->def))
        return -1;

    map = def->cpumask;

    for (i = 0; i < virBitmapSize(map); i++) {
        if (virBitmapIsBitSet(map, i)) {
            snprintf(path, sizeof(path), "%s/cpu%d/online", SYSFS_CPU_PATH, i);

            if ((fd = open(path, O_RDWR)) < 0) {
                virReportError(VIR_ERR_OPEN_FAILED, _("%s"), path);
                goto out;
            }

            chr = '0';

            do {
                if (pwrite(fd, &chr, sizeof(chr), 0) < sizeof(chr)) {
                    close(fd);
                    virReportError(VIR_ERR_WRITE_FAILED, _("%s"), path);
                    goto out;
                }
            } while ((rc = pread(fd, &online, sizeof(online), 0)) > 0 &&
                     online != '0');

            close(fd);

            if (rc <= 0) {
                virReportError(VIR_ERR_READ_FAILED, _("%s"), path);
                goto out;
            }

            if ((fd = open(ACRN_OFFLINE_PATH, O_WRONLY)) < 0) {
                virReportError(VIR_ERR_OPEN_FAILED, _(ACRN_OFFLINE_PATH));
                goto out;
            }

            chr += i;

            if (write(fd, &chr, sizeof(chr)) < sizeof(chr)) {
                close(fd);
                virReportError(VIR_ERR_WRITE_FAILED, _(ACRN_OFFLINE_PATH));
                goto out;
            }

            close(fd);
        }
    }

    ret = 0;

out:
    return ret;
}

static void
acrnAddVirtioConsoleCmd(virBufferPtr buf, virDomainChrDefPtr chr)
{
    if (chr->deviceType != VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE ||
        chr->targetType != VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO)
        return;

    switch (chr->source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAddLit(buf, ",@pty:pty_port");
        break;
    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferAsprintf(buf, ",@tty:tty_port=%s",
                          chr->source->data.file.path);
        break;
    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(buf, ",@file:file_port=%s",
                          chr->source->data.file.path);
        break;
    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAddLit(buf, ",@stdio:stdio_port");
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(buf, ",socket:socket_file_name=%s:%s",
                          chr->source->data.nix.path,
                          chr->source->data.nix.listen ?
                          "server" : "client");
        break;
    default:
        return;
    }
}

struct acrnCmdDeviceData {
    virCommandPtr cmd;
    bool lpc;
};

static int
acrnCommandAddDeviceArg(virDomainDefPtr def,
                        virDomainDeviceDefPtr dev,
                        virDomainDeviceInfoPtr info,
                        void *opaque)
{
    struct acrnCmdDeviceData *data = opaque;
    virCommandPtr cmd = data->cmd;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK: {
        virDomainDiskDefPtr disk = dev->data.disk;

        if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
            /*
             * VIR_DOMAIN_DISK_DEVICE_DISK &&
             * VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI
             */
            virCommandAddArg(cmd, "-s");
            virCommandAddArgFormat(cmd, "%u:%u:%u,virtio-blk,%s",
                                   info->addr.pci.bus,
                                   info->addr.pci.slot,
                                   info->addr.pci.function,
                                   virDomainDiskGetSource(disk));
        } else { /* VIR_DOMAIN_DISK_BUS_SATA */
            size_t i;

            for (i = 0; i < def->ncontrollers; i++) {
                virDomainControllerDefPtr ctrl = def->controllers[i];

                if (ctrl->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA &&
                    ctrl->idx == disk->info.addr.drive.controller) {
                    virCommandAddArg(cmd, "-s");
                    virCommandAddArgFormat(cmd, "%u:%u:%u,ahci-%s,%s",
                                           ctrl->info.addr.pci.bus,
                                           ctrl->info.addr.pci.slot,
                                           ctrl->info.addr.pci.function,
                                           (disk->device ==
                                                VIR_DOMAIN_DISK_DEVICE_DISK) ?
                                                "hd" : "cd",
                                           virDomainDiskGetSource(disk));
                    /* a SATA controller can only have one disk attached */
                    break;
                }
            }
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_NET: {
        virDomainNetDefPtr net = dev->data.net;
        char macstr[VIR_MAC_STRING_BUFLEN];

        virCommandAddArg(cmd, "-s");
        virCommandAddArgFormat(cmd, "%u:%u:%u,virtio-net,%s,mac=%s",
                               info->addr.pci.bus,
                               info->addr.pci.slot,
                               info->addr.pci.function,
                               net->ifname,
                               virMacAddrFormat(&net->mac, macstr));
        break;
    }
    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        virDomainHostdevDefPtr hostdev = dev->data.hostdev;
        virDomainHostdevSubsysPtr subsys = &hostdev->source.subsys;

        virCommandAddArg(cmd, "-s");

        if (subsys->type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            virDomainHostdevSubsysUSBPtr usbsrc = &subsys->u.usb;

            if (!usbsrc->autoAddress) {
                virReportError(VIR_ERR_NO_SOURCE, _("usb hostdev"));
                return -1;
            }

            virCommandAddArgFormat(cmd, "%u:%u:%u,passthru,%x/%x/0",
                                   info->addr.pci.bus,
                                   info->addr.pci.slot,
                                   info->addr.pci.function,
                                   usbsrc->bus, usbsrc->device);
        } else { /* VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI */
            virDomainHostdevSubsysPCIPtr pcisrc = &subsys->u.pci;

            virCommandAddArgFormat(cmd, "%u:%u:%u,passthru,%x/%x/%x",
                                   info->addr.pci.bus,
                                   info->addr.pci.slot,
                                   info->addr.pci.function,
                                   pcisrc->addr.bus,
                                   pcisrc->addr.slot,
                                   pcisrc->addr.function);
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_CONTROLLER: {
        virDomainControllerDefPtr ctrl = dev->data.controller;
        size_t i;
        bool found = false;
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        /* PCI hostbridge is always included */
        if (ctrl->type == VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL) {
            for (i = 0; i < def->nconsoles; i++) {
                virDomainChrDefPtr chr = def->consoles[i];

                if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
                    chr->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL &&
                    chr->info.addr.vioserial.controller == ctrl->idx) {
                    if (!found) {
                        virBufferAsprintf(&buf, "%u:%u:%u,virtio-console",
                                          info->addr.pci.bus,
                                          info->addr.pci.slot,
                                          info->addr.pci.function);
                        found = true;
                    }

                    acrnAddVirtioConsoleCmd(&buf, chr);
                }
            }
        }

        if (found) {
            virCommandAddArg(cmd, "-s");
            virCommandAddArgBuffer(cmd, &buf);
            virBufferFreeAndReset(&buf);
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_CHR: {
        virDomainChrDefPtr chr = dev->data.chr;

        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;

            if (!data->lpc) {
                virCommandAddArgList(cmd, "-s", "1:0,lpc", NULL);
                data->lpc = true;
            }

            virBufferAsprintf(&buf, "com%d,", chr->target.port + 1);

            switch (chr->source->type) {
            case VIR_DOMAIN_CHR_TYPE_DEV:
                virBufferAsprintf(&buf, "%s", chr->source->data.file.path);
                break;
            case VIR_DOMAIN_CHR_TYPE_STDIO:
                virBufferAddLit(&buf, "stdio");
                break;
            case VIR_DOMAIN_CHR_TYPE_TCP: {
                unsigned int tcpport;

                if (virStrToLong_ui(chr->source->data.tcp.service,
                                    NULL, 10, &tcpport) < 0) {
                    virBufferFreeAndReset(&buf);
                    virReportError(VIR_ERR_NO_SOURCE,
                                   _("serial over tcp"));
                    return -1;
                }

                virBufferAsprintf(&buf, "tcp:%u", tcpport);
                break;
            }
            default:
                virBufferFreeAndReset(&buf);
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("serial type %s"),
                               virDomainChrTypeToString(chr->source->type));
                return -1;
            }

            virCommandAddArg(cmd, "-l");
            virCommandAddArgBuffer(cmd, &buf);
            virBufferFreeAndReset(&buf);
        } else { /* VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE */
            if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virBuffer buf = VIR_BUFFER_INITIALIZER;

                virBufferAsprintf(&buf, "%u:%u:%u,virtio-console",
                                  info->addr.pci.bus,
                                  info->addr.pci.slot,
                                  info->addr.pci.function);
                acrnAddVirtioConsoleCmd(&buf, chr);

                virCommandAddArg(cmd, "-s");
                virCommandAddArgBuffer(cmd, &buf);
                virBufferFreeAndReset(&buf);
            }
            /*
             * VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL was
             * already dealt with when its controller was reached.
             */
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_RNG:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("device type %s"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    return 0;
}

static virCommandPtr
acrnBuildStartCmd(virDomainDefPtr def)
{
    virCommandPtr cmd;
    struct acrnCmdDeviceData data = { 0 };
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!def)
        return NULL;

    if (!(cmd = virCommandNew(ACRN_DM_PATH))) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    /* ACPI */
    if (def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON)
        virCommandAddArg(cmd, "-A");

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%lluM",
                           VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

    /* UUID */
    virCommandAddArg(cmd, "-U");
    virCommandAddArg(cmd, virUUIDFormat(def->uuid, uuidstr));

    /* PCI hostbridge */
    virCommandAddArgList(cmd, "-s", "0:0,hostbridge", NULL);

    data.cmd = cmd;

    /* Devices */
    if (virDomainDeviceInfoIterate(def, acrnCommandAddDeviceArg, &data)) {
        virCommandFree(cmd);
        return NULL;
    }

    /* Bootloader */
    if (def->os.loader && def->os.loader->path) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        if (def->os.loader->readonly == VIR_TRISTATE_BOOL_NO)
            virBufferAddLit(&buf, "w,");
        virBufferAdd(&buf, def->os.loader->path, -1);

        virCommandAddArg(cmd, "--ovmf");
        virCommandAddArgBuffer(cmd, &buf);
        virBufferFreeAndReset(&buf);
    } else if (def->os.kernel && def->os.cmdline) {
        virCommandAddArg(cmd, "-k");
        virCommandAddArg(cmd, def->os.kernel);
        virCommandAddArg(cmd, "-B");
        virCommandAddArg(cmd, def->os.cmdline);

        if (def->os.initrd) {
            virCommandAddArg(cmd, "-r");
            virCommandAddArg(cmd, def->os.initrd);
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("boot policy"));
    }

    /* VM name */
    virCommandAddArg(cmd, def->name);

    return cmd;
}

static int
acrnProcessStart(virDomainObjPtr vm)
{
    virCommandPtr cmd;
    int ret = -1;

    if (!(cmd = acrnBuildStartCmd(vm->def)))
        goto cleanup;

    virCommandDaemonize(cmd);

    VIR_DEBUG("Starting domain '%s'", vm->def->name);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (sscanf(vm->def->name, "vm%d", &vm->def->id) != 1)
        vm->def->id = 0;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);
    ret = 0;

cleanup:
    virCommandFree(cmd);
    return ret;
}

static virDomainPtr
acrnDomainCreateXML(virConnectPtr conn,
                    const char *xml,
                    unsigned int flags)
{
    acrnConnectPtr privconn = conn->privateData;
    virDomainPtr dom = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr vm = NULL;
    virCapsPtr caps = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    /* VIR_DOMAIN_START_AUTODESTROY is not supported yet */
    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(caps = acrnDriverGetCapabilities(privconn)))
        return NULL;

    if (!(def = virDomainDefParseString(xml, caps, privconn->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup;

    vm = virDomainObjListAdd(privconn->domains, def,
                             privconn->xmlopt,
                             VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                             VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE, NULL);
    if (vm == NULL)
        goto cleanup;

    def = NULL;

    if (acrnProcessPrepareDomain(conn, vm) < 0 ||
        acrnProcessStart(vm) < 0) {
        if (!vm->persistent) {
            virDomainObjListRemove(privconn->domains, vm);
            vm = NULL;
        }
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virDomainDefFree(def);
    virObjectUnref(caps);

    return dom;
}

static virDrvOpenStatus
acrnConnectOpen(virConnectPtr conn,
                virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                virConfPtr conf ATTRIBUTE_UNUSED,
                unsigned int flags)
{
     virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

     if (conn->uri == NULL) {
         if (acrn_driver == NULL)
             return VIR_DRV_OPEN_DECLINED;

         if (!(conn->uri = virURIParse("acrn:///system")))
             return VIR_DRV_OPEN_ERROR;
     } else {
         if (STRNEQ_NULLABLE(conn->uri->scheme, "acrn"))
             return VIR_DRV_OPEN_DECLINED;

         if (conn->uri->server)
             return VIR_DRV_OPEN_DECLINED;

         if (STRNEQ_NULLABLE(conn->uri->path, "/system")) {
             virReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unexpected ACRN URI path '%s', try acrn:///system"),
                            conn->uri->path ? conn->uri->path : "NULL");
             return VIR_DRV_OPEN_ERROR;
         }

         if (acrn_driver == NULL) {
             virReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("ACRN state driver is not active"));
             return VIR_DRV_OPEN_ERROR;
         }
     }

     conn->privateData = acrn_driver;

     return VIR_DRV_OPEN_SUCCESS;
}

static int
acrnConnectClose(virConnectPtr conn)
{
    /* autodestroy is not supported yet */
    conn->privateData = NULL;
    return 0;
}

static virCapsPtr
virAcrnCapsBuild(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if (!(caps = virCapabilitiesNew(virArchFromHost(), false, false)))
        return NULL;

    if (!(guest = virCapabilitiesAddGuest(caps,
                                          VIR_DOMAIN_OSTYPE_HVM,
                                          VIR_ARCH_X86_64, "acrn-dm",
                                          NULL, 0, NULL)))
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest,
                                       VIR_DOMAIN_VIRT_ACRN,
                                       NULL, NULL, 0, NULL))
        goto error;

    caps->host.cpu = virCPUProbeHost(caps->host.arch);
    return caps;

error:
    virObjectUnref(caps);
    return NULL;
}

static int
acrnStateCleanup(void)
{
    VIR_DEBUG("ACRN state cleanup");

    if (!acrn_driver)
        return -1;

    virObjectUnref(acrn_driver->domains);
    virObjectUnref(acrn_driver->xmlopt);
    virObjectUnref(acrn_driver->caps);
    virMutexDestroy(&acrn_driver->lock);
    VIR_FREE(acrn_driver);

    return 0;
}

static int
acrnStateInitialize(bool privileged,
                    virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                    void *opaque ATTRIBUTE_UNUSED)
{
    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return 0;
    }

    if (VIR_ALLOC(acrn_driver) < 0)
        return -1;

    if (virMutexInit(&acrn_driver->lock) < 0) {
        VIR_FREE(acrn_driver);
        return -1;
    }

    if (!(acrn_driver->caps = virAcrnCapsBuild()))
        goto cleanup;

    if (!(acrn_driver->xmlopt = virAcrnDriverCreateXMLConf()))
        goto cleanup;

    if (!(acrn_driver->domains = virDomainObjListNew()))
        goto cleanup;

    return 0;

 cleanup:
    acrnStateCleanup();
    return -1;
}

static virHypervisorDriver acrnHypervisorDriver = {
    .name = "ACRN",
    .connectOpen = acrnConnectOpen, /* 0.0.1 */
    .connectClose = acrnConnectClose, /* 0.0.1 */
    .connectListAllDomains = acrnConnectListAllDomains, /* 0.0.1 */
    .domainCreateXML = acrnDomainCreateXML, /* 0.0.1 */
    .domainLookupByName = acrnDomainLookupByName, /* 0.0.1 */
    .domainShutdown = acrnDomainShutdown, /* 0.0.1 */
    .domainDestroy = acrnDomainDestroy, /* 0.0.1 */
    .domainGetInfo = acrnDomainGetInfo,  /* 0.0.1 */
};

static virConnectDriver acrnConnectDriver = {
    .hypervisorDriver = &acrnHypervisorDriver,
};

static virStateDriver acrnStateDriver = {
    .name = "ACRN",
    .stateInitialize = acrnStateInitialize,
    .stateCleanup = acrnStateCleanup,
};

int
acrnRegister(void)
{
    if (virRegisterConnectDriver(&acrnConnectDriver, true) < 0)
        return -1;
    if (virRegisterStateDriver(&acrnStateDriver) < 0)
        return -1;
    return 0;
}
