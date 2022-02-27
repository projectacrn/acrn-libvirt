#include <config.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <uuid/uuid.h>
#include "configmake.h"
#include "datatypes.h"
#include "node_device_conf.h"
#include "virdomainobjlist.h"
#include "virerror.h"
#include "viralloc.h"
#include "virutil.h"
#include "cpu/cpu.h"
#include "virhostcpu.h"
#include "vircommand.h"
#include "virthread.h"
#include "virstring.h"
#include "virfile.h"
#include "virhostdev.h"
#include "virnodesuspend.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"
#include "virfdstream.h"
#include "virlog.h"
#include "domain_event.h"
#include "viraccessapicheck.h"
#include "acrn_driver.h"
#include "acrn_domain.h"
#include "acrn_monitor.h"
#include "acrn_manager.h"

#define VIR_FROM_THIS VIR_FROM_ACRN
#define ACRN_DM_PATH            "/usr/bin/acrn-dm"
#define ACRN_CTL_PATH           "/usr/bin/acrnctl"
#define ACRN_OFFLINE_PATH       "/sys/devices/virtual/misc/acrn_hsm/remove_cpu"
#define SYSFS_CPU_PATH          "/sys/devices/system/cpu"
#define ACRN_AUTOSTART_DIR      SYSCONFDIR "/libvirt/acrn/autostart"
#define ACRN_CONFIG_DIR         SYSCONFDIR "/libvirt/acrn"
#define ACRN_STATE_DIR          RUNSTATEDIR "/libvirt/acrn"
#define ACRN_MONITOR_DIR        "/var/lib/libvirt/acrn"
#define ACRN_MANAGER_DIR        "/var/lib/life_mngr"
#define ACRN_NET_GENERATED_TAP_PREFIX   "tap"
#define ACRN_PI_VERSION         (0x100)

VIR_LOG_INIT("acrn.acrn_driver");

typedef struct _acrnConnect acrnConnect;
typedef struct _acrnConnect *acrnConnectPtr;
struct _acrnConnect {
    virMutex lock;
    virNodeInfo nodeInfo;
    virDomainObjListPtr domains;
    virCapsPtr caps;
    virDomainXMLOptionPtr xmlopt;
    virObjectEventStatePtr domainEventState;
    virHostdevManagerPtr hostdevMgr;
    size_t *vcpuAllocMap;
};

typedef struct _acrnDomainNamespaceDef acrnDomainNamespaceDef;
typedef acrnDomainNamespaceDef *acrnDomainNamespaceDefPtr;
struct _acrnDomainNamespaceDef {
    size_t num_args;
    char **args;
};

#define MAX_NUM_VMS     (64)

struct acrnAutostartData {
    acrnConnectPtr driver;
    virConnectPtr conn;
};
static acrnConnectPtr acrn_driver = NULL;

static void
acrnDriverLock(acrnConnectPtr driver)
{
    virMutexLock(&driver->lock);
}

static void
acrnDriverUnlock(acrnConnectPtr driver)
{
    virMutexUnlock(&driver->lock);
}

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

static bool
acrnIsRtvm(virDomainDefPtr def)
{
    acrnDomainXmlNsDefPtr nsdef = def->namespaceData;

    return (nsdef && nsdef->rtvm);
}

static int
acrnAllocateVcpus(virBitmapPtr pcpus, size_t maxvcpus,
                  size_t *allocMap, virBitmapPtr vcpus)
{
    ssize_t pos;

    if (maxvcpus == 0)
        return -1;
    pos = -1;

    /* successful - update allocation map */
    while (((pos = virBitmapNextSetBit(pcpus, pos)) >= 0) && (maxvcpus > 0)) {

        if (pos >= acrn_driver->nodeInfo.cpus) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                            _("pCPU[%ld] doesn't exist"), pos);
            return -1;
        }
        if (virBitmapSetBit(vcpus, pos) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                            _("failed to set bit %ld in cpu affinity"), pos);
            return -1;
        }
        allocMap[pos] += 1;
        maxvcpus --;
        VIR_DEBUG("pCPU[%ld]: %lu vCPU%s allocated",
                  pos, allocMap[pos],
                  (allocMap[pos] > 1) ? "s" : "");
    }

    return 0;
}

static int
acrnFreeVcpus(virBitmapPtr vcpus, size_t *allocMap)
{
    ssize_t pos = -1;
    int ret = 0;

    if (!vcpus || !allocMap)
        return -1;

    /* update allocation map */
    while ((pos = virBitmapNextSetBit(vcpus, pos)) >= 0) {
        if (allocMap[pos]) {
            allocMap[pos] -= 1;

            VIR_DEBUG("pCPU[%ld]: %lu vCPU%s allocated",
                      pos, allocMap[pos],
                      (allocMap[pos] > 1) ? "s" : "");
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("vCPU allocation map error (bit %ld)"),
                           pos);
            ret = -1;
        }
    }

    return ret;
}

static int
acrnSetOnlineVcpus(virDomainDefPtr def, virBitmapPtr vcpus)
{
    return virDomainDefSetVcpus(def, virBitmapCountBits(vcpus));
}

static int
acrnProcessPrepareDomain(virDomainObjPtr vm, size_t *allocMap)
{
    virDomainDefPtr def;
    acrnDomainObjPrivatePtr priv;
    int ret = -1;

    if (!vm || !(def = vm->def))
        return -1;

    priv = vm->privateData;
    if (def->cpumask == NULL || virBitmapIsAllClear(def->cpumask)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("cpuset is empty"));
        goto cleanup;
    }
    virBitmapShrink(def->cpumask, acrn_driver->nodeInfo.cpus);
    if (priv->cpuAffinitySet)
        virBitmapFree(priv->cpuAffinitySet);
    if (!(priv->cpuAffinitySet = virBitmapNew(acrn_driver->nodeInfo.cpus))) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }

    /* vCPU placement */
    if (acrnAllocateVcpus(def->cpumask,
                          def->maxvcpus, allocMap,
                          priv->cpuAffinitySet) < 0)
        goto cleanup;

    if (acrnSetOnlineVcpus(def, priv->cpuAffinitySet) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("acrnSetOnlineVcpus failed"));
        acrnFreeVcpus(priv->cpuAffinitySet, allocMap);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret < 0 && priv->cpuAffinitySet) {
        virBitmapFree(priv->cpuAffinitySet);
        priv->cpuAffinitySet = NULL;
    }
    return ret;
}

static int
acrnCreateTapDev(virDomainNetDefPtr net, const unsigned char *uuid)
{
    int tapfd = -1, ret = -1;

    if (!net->ifname ||
        !STRPREFIX(net->ifname, ACRN_NET_GENERATED_TAP_PREFIX)) {
        if (net->ifname) {
            VIR_WARN("Tap name '%s' not supported", net->ifname);
            VIR_FREE(net->ifname);
        }
        net->ifname = g_strdup(ACRN_NET_GENERATED_TAP_PREFIX "%d");
    }

    if (virNetDevTapCreateInBridgePort(
                virDomainNetGetActualBridgeName(net),
                &net->ifname, &net->mac,
                uuid, NULL, &tapfd, 1,
                virDomainNetGetActualVirtPortProfile(net),
                virDomainNetGetActualVlan(net),
                virDomainNetGetActualPortOptionsIsolated(net),
                NULL, net->mtu, NULL,
                VIR_NETDEV_TAP_CREATE_IFUP |
                VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
        virReportError(VIR_WAR_NO_NETWORK, "%s", net->ifname);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (tapfd >= 0)
        VIR_FORCE_CLOSE(tapfd);
    return ret;
}

static void
acrnNetCleanup(virDomainObjPtr vm)
{
    size_t i;

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];
        virDomainNetType actualType = virDomainNetGetActualType(net);

        if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (net->ifname) {
                int retries = 5;

                ignore_value(virNetDevBridgeRemovePort(
                                virDomainNetGetActualBridgeName(net),
                                net->ifname));

                /*
                 * FIXME
                 * There is currently no way to reliably know when the
                 * shutdown process is complete.
                 */
                while (virNetDevTapDelete(net->ifname, NULL) < 0 && retries--)
                    sleep(1);
            }
        }
    }
}

static int
acrnCreateTty(virDomainObjPtr vm, virDomainChrDefPtr chr)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;
    int ttyfd;
    char *ttypath;

    if (priv->nttys == G_N_ELEMENTS(priv->ttys)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("too many ttys (max = %lu)"),
                       G_N_ELEMENTS(priv->ttys));
        return -1;
    }

    if (virFileOpenTty(&ttyfd, &ttypath, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virFileOpenTty failed"));
        return -1;
    }

    priv->ttys[priv->nttys].slave = g_strdup(ttypath);
    priv->ttys[priv->nttys].fd = ttyfd;
    priv->nttys++;

    if (chr->source->data.file.path)
        VIR_FREE(chr->source->data.file.path);
    chr->source->data.file.path = ttypath;

    return 0;
}

static void
acrnTtyCleanup(virDomainObjPtr vm)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;

    acrnDomainTtyCleanup(priv);
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
    virDomainObjPtr vm;
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

        if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
            acrnCreateTapDev(net, def->uuid) < 0)
                return -1;

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
            case VIR_DOMAIN_CHR_TYPE_PTY:
                if (acrnCreateTty(data->vm, chr) < 0)
                    return -1;
                virBufferAsprintf(&buf, "%s", chr->source->data.file.path);
                break;
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
            /* may be an implicit serial device - ignore */
            if (chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE ||
                chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL) {
                VIR_DEBUG("ignore implicit serial device");
                break;
            }

            /* VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO */
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
acrnBuildStartCmd(virDomainObjPtr vm)
{
    virDomainDefPtr def;
    virCommandPtr cmd;
    acrnDomainObjPrivatePtr priv;
    acrnDomainXmlNsDefPtr nsdef;
    struct acrnCmdDeviceData data = { 0 };
    char *pcpus;
    size_t i;
    char *monitor_path;

    if (!vm || !(def = vm->def))
        return NULL;

    if (!(cmd = virCommandNew(ACRN_DM_PATH))) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    priv = vm->privateData;

    /* CPU */
    pcpus = virBitmapFormat(priv->cpuAffinitySet);
    virCommandAddArgList(cmd, "--cpu_affinity", pcpus, NULL);
    VIR_FREE(pcpus);

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%lluM",
                           VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

    /* RTVM */
    if (acrnIsRtvm(def))
        virCommandAddArgList(cmd,
                             "--lapic_pt",
                             "--virtio_poll", "1000000",
                             NULL);

    /* PCI hostbridge */
    virCommandAddArgList(cmd, "-s", "0:0,hostbridge", NULL);

    data.vm = vm;
    data.cmd = cmd;

    /* Devices */
    if (virDomainDeviceInfoIterate(def, acrnCommandAddDeviceArg, &data)) {
        virCommandFree(cmd);
        return NULL;
    }

    nsdef = def->namespaceData;

    /* User-defined command-line args */
    if (nsdef) {
        for (i = 0; i < nsdef->nargs; i++)
            virCommandAddArg(cmd, nsdef->args[i]);
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

    /* Command monitor */
    monitor_path = g_strdup_printf("%s/domain-%s/monitor.sock", ACRN_MONITOR_DIR, vm->def->name);
    virCommandAddArgList(cmd, "--cmd_monitor", monitor_path, NULL);

    return cmd;
}

static int
acrnProcessPrepareMonitorChr(virDomainChrSourceDefPtr monConfig,
                             const char *domainDir)
{
    monConfig->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    monConfig->data.nix.listen = true;

    monConfig->data.nix.path = g_strdup_printf("%s/monitor.sock", domainDir);
    return 0;
}

static int
acrnProcessWaitForMonitor(virDomainObjPtr vm, acrnMonitorStopCallback stop)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;
    virDomainChrSourceDefPtr config = priv->monConfig;
    acrnMonitorPtr mon = NULL;

    if (!priv->libDir)
        priv->libDir = g_strdup_printf("%s/domain-%s", ACRN_MONITOR_DIR, vm->def->name);
    if (virFileMakePath(priv->libDir) < 0) {
	    virReportSystemError(errno,
			                _("Failed to mkdir %s"),
			                priv->libDir);
	    return -1;
    }
    if (!(config = virDomainChrSourceDefNew(acrn_driver->xmlopt)))
        return -1;
    VIR_DEBUG("Preparing monitor state");
    if (acrnProcessPrepareMonitorChr(config, priv->libDir) < 0)
        return -1;
    VIR_DEBUG("Monitor UNIX socket path:%s", config->data.nix.path);

    mon = acrnMonitorOpen(vm, config, stop);

    priv->mon = mon;

    if (priv->mon == NULL) {
        VIR_INFO("Failed to connect monitor for %s", vm->def->name);
        return -1;
    }
    VIR_DEBUG("acrnProcessWaitForMonitor:end");
    return 0;
}
static int
acrnProcessWaitForManager(virDomainObjPtr vm, acrnManagerStopCallback stop)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;
    virDomainChrSourceDefPtr config = priv->mgrConfig;
    acrnManagerPtr mon = NULL;

    if (!priv->mgrDir)
        priv->mgrDir = g_strdup_printf("%s", ACRN_MANAGER_DIR);

    if (!(config = virDomainChrSourceDefNew(acrn_driver->xmlopt)))
        return -1;

    if (acrnProcessPrepareMonitorChr(config, priv->mgrDir) < 0)
        return -1;
    VIR_DEBUG("Manager UNIX socket path:%s", config->data.nix.path);

    mon = acrnManagerOpen(vm, config, stop);

    priv->mgr = mon;

    if (priv->mgr == NULL) {
        VIR_INFO("Failed to connect acrn manager for %s", vm->def->name);
        return -1;
    }
    VIR_DEBUG("acrnProcessWaitForManager:end");
    return 0;
}
static virCommandPtr
acrnRunStartCommand(virDomainObjPtr vm)
{
    int ret = -1;
    virCommandPtr cmd;

    cmd = acrnBuildStartCmd(vm);
    if (!cmd)
        return NULL;

    virCommandRawStatus(cmd);
    ret = virCommandRunAsync(cmd, &vm->pid);
    if (ret < 0) {
        virCommandFree(cmd);
        cmd = NULL;
        virReportSystemError(errno, "%s", _("virCommandRunAsync failed"));
    }

    return cmd;
}

static void acrnProcessStopCallback(virDomainObjPtr vm);

static int
acrnProcessStart(virDomainObjPtr vm)
{
    virCommandPtr cmd;
    int ret = -1;

    VIR_DEBUG("Starting domain '%s'", vm->def->name);

    cmd = acrnRunStartCommand(vm);
    if (!cmd)
        goto cleanup;

    vm->def->id = vm->pid;

    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, VIR_DOMAIN_RUNNING_BOOTED);

    VIR_DEBUG("Waiting for monitor to show up");
    if (acrnProcessWaitForMonitor(vm, &acrnProcessStopCallback) < 0)
            goto cleanup;

    if (virDomainObjSave(vm, acrn_driver->xmlopt,
                        ACRN_STATE_DIR) < 0)
            goto cleanup;

    return 0;

cleanup:
    if (cmd) {
        virCommandFree(cmd);
    }

    vm->pid = -1;
    acrnNetCleanup(vm);
    acrnTtyCleanup(vm);
    return ret;
}
static int
acrnAutostartDomain(virDomainObjPtr vm, void *opaque)
{
    const struct acrnAutostartData *data = opaque;
    int ret = 0;
    acrnConnectPtr privconn = data->driver;
    acrnDomainObjPrivatePtr priv;

    virObjectLock(vm);
    if (vm->autostart && !virDomainObjIsActive(vm)) {
        virResetLastError();
        priv = vm->privateData;

        if (acrnProcessPrepareDomain(vm, privconn->vcpuAllocMap) < 0)
            goto cleanup;
        if (acrnProcessStart(vm) < 0) {
            /* domain must be persistent */
            acrnFreeVcpus(priv->cpuAffinitySet, privconn->vcpuAllocMap);
            goto cleanup;
        }
        if (ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Failed to autostart VM '%s': %s"),
                        vm->def->name, virGetLastErrorMessage());
        }
    }
cleanup:
	virObjectUnlock(vm);
	return ret;
}

static void
acrnAutostartDomains(acrnConnectPtr driver)
{
    virConnectPtr conn = virConnectOpen("acrn:///system");
    /* Ignoring NULL conn which is mostly harmless here */

    struct acrnAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains, false, acrnAutostartDomain, &data);

    virObjectUnref(conn);
}

static int
acrnDomainShutdownMonitor(virDomainObjPtr vm)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;

    return acrnMonitorSystemPowerdown(priv->mon);
}
static int
acrnDomainShutdownManager(virDomainObjPtr vm)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;

    return acrnManagerSystemPowerdown(priv->mgr);
}

static void
acrnProcessCleanup(virDomainObjPtr vm, int reason, size_t *allocMap)
{
    acrnDomainObjPrivatePtr priv = vm->privateData;

    /* clean up network interfaces */
    acrnNetCleanup(vm);

    /* clean up ttys */
    acrnTtyCleanup(vm);

    acrnManagerClose(priv->mgr);
    if (priv->mgrConfig) {
        if (priv->mgrConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(priv->mgrConfig->data.nix.path);
        virObjectUnref(priv->mgrConfig);
        priv->mgrConfig = NULL;
    }

    acrnMonitorClose(priv->mon);
    if (priv->monConfig) {
        if (priv->monConfig->type == VIR_DOMAIN_CHR_TYPE_UNIX)
            unlink(priv->monConfig->data.nix.path);
        virObjectUnref(priv->monConfig);
        priv->monConfig = NULL;
    }

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);

    vm->pid = -1;
    vm->def->id = -1;

    acrnFreeVcpus(priv->cpuAffinitySet, allocMap);
    virDomainDeleteConfig(ACRN_STATE_DIR, NULL, vm);
}

static int
acrnProcessShutdown(virDomainObjPtr vm, int reason)
{
    virDomainDefPtr def = vm->def;
    int ret = 0;

    VIR_DEBUG("Waiting for acrn manager");
    if (acrnProcessWaitForManager(vm, NULL) < 0)
        return -1;

    VIR_DEBUG("Stopping domain '%s'", def->name);
    if (acrnDomainShutdownManager(vm) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                    _("Fail to stop domain '%s'"), def->name);
        ret = -1;
    }
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTDOWN, reason);

    return ret;
}

static int
acrnProcessStop(virDomainObjPtr vm, int reason)
{
    virDomainDefPtr def = vm->def;
    int ret = 0;

    VIR_DEBUG("Stopping domain '%s'", def->name);

    if (acrnDomainShutdownMonitor(vm) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                    _("Fail to stop domain '%s'"), def->name);
        ret = -1;
    }
    virDomainObjSetState(vm, VIR_DOMAIN_SHUTDOWN, reason);

    return ret;
}

static void
acrnProcessStopCallback(virDomainObjPtr vm)
{
    int reason;
    acrnDomainObjPrivatePtr priv = vm->privateData;
    acrnMonitorPtr mon = priv->mon;

    VIR_DEBUG("acrnProcessStopCallback '%s'", vm->def->name);
    reason = acrnMonitorGetReason(mon);
    acrnProcessCleanup(vm, reason, acrn_driver->vcpuAllocMap);
    if (!vm->persistent)
        virDomainObjListRemove(acrn_driver->domains, vm);
}

static virDomainPtr
acrnDomainLookupByUUID(virConnectPtr conn,
                       const unsigned char *uuid)
{
    acrnConnectPtr privconn = conn->privateData;
    virDomainObjPtr vm;
    virDomainPtr dom = NULL;

    vm = virDomainObjListFindByUUID(privconn->domains, uuid);

    if (!vm) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s'"), uuidstr);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return dom;
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
acrnDomainShutdown(virDomainPtr dom)
{
    acrnConnectPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    virObjectEventPtr event = NULL;
    int ret = -1;

    acrnDriverLock(privconn);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain is not running"));
        goto cleanup;
    }

    if (acrnProcessShutdown(vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN) < 0) {
        goto cleanup;
    }

    if (!(event = virDomainEventLifecycleNewFromObj(
                    vm,
                    VIR_DOMAIN_EVENT_STOPPED,
                    VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN)))
        goto cleanup;

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    acrnDriverUnlock(privconn);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainDestroy(virDomainPtr dom)
{
    acrnConnectPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm;
    virDomainState state;
    virObjectEventPtr event = NULL;
    int reason, ret = -1, val = 0;

    acrnDriverLock(privconn);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain is not running"));
        goto cleanup;
    }

    state = virDomainObjGetState(vm, &reason);

    if (state == VIR_DOMAIN_SHUTOFF) {
        if (reason != VIR_DOMAIN_SHUTOFF_DESTROYED)
            virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                                 VIR_DOMAIN_SHUTOFF_DESTROYED);
    } else {
        val = acrnProcessStop(vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
    }

    event = virDomainEventLifecycleNewFromObj(
                vm,
                VIR_DOMAIN_EVENT_STOPPED,
                VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (!vm->persistent &&
        (state != VIR_DOMAIN_SHUTOFF ||
         reason != VIR_DOMAIN_SHUTOFF_DESTROYED)) {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
    }

    if (!event)
        goto cleanup;

    ret = val;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    acrnDriverUnlock(privconn);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainIsPersistent(virDomainPtr domain)
{
    virDomainObjPtr obj;
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

static int
acrnDomainGetAutostart(virDomainPtr domain, int *autostart)
{
    virDomainObjPtr vm;
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
    virDomainObjPtr vm;
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
            if (virFileMakePath(ACRN_AUTOSTART_DIR) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     ACRN_AUTOSTART_DIR);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s' to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (unlink(autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
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
acrnDomainGetState(virDomainPtr domain,
                   int *state,
                   int *reason,
                   unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    *state = virDomainObjGetState(vm, reason);
    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
acrnDomainGetVcpus(virDomainPtr domain,
                   virVcpuInfoPtr info,
                   int maxinfo,
                   unsigned char *cpumaps,
                   int maplen)
{
    virDomainObjPtr vm;
    virDomainDefPtr def;
    acrnDomainObjPrivatePtr priv;
    struct timeval tv;
    virBitmapPtr cpumap = NULL;
    unsigned long long statbase;
    int i, ret = -1;
    ssize_t pos;

    if (!(vm = acrnDomObjFromDomain(domain)))
        return -1;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("cannot list vcpus for an inactive domain"));
        goto cleanup;
    }

    if (!(def = vm->def) || !(priv = vm->privateData))
        goto cleanup;

    /* clamp to actual number of vcpus */
    if (maxinfo > virDomainDefGetVcpus(vm->def))
        maxinfo = virDomainDefGetVcpus(vm->def);

    memset(info, 0, sizeof(*info) * maxinfo);

    if (cpumaps) {
        memset(cpumaps, 0, maxinfo * maplen);

        if (!(cpumap = virBitmapNew(maplen * CHAR_BIT))) {
            virReportError(VIR_ERR_NO_MEMORY, NULL);
            goto cleanup;
        }
    }

    if (!priv->cpuAffinitySet) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("cpumask missing"));
        goto cleanup;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        goto cleanup;
    }

    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;
    statbase /= virBitmapCountBits(priv->cpuAffinitySet);

    for (i = 0, pos = -1; i < maxinfo; i++) {
        virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(def, i);

        if (!vcpu->online)
            continue;

        if ((pos = virBitmapNextSetBit(priv->cpuAffinitySet, pos)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cpu missing in cpumask"));
            goto cleanup;
        }

        if (cpumaps) {
            virBitmapClearAll(cpumap);

            if (virBitmapSetBit(cpumap, pos) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("failed to set bit %ld in cpumap"), pos);
                goto cleanup;
            }

            virBitmapToDataBuf(cpumap, VIR_GET_CPUMAP(cpumaps, maplen, i),
                               maplen);
        }

        info[i].number = i;
        info[i].state = VIR_VCPU_RUNNING;
        info[i].cpu = pos;

        /* FIXME fake an increasing cpu time value */
        info[i].cpuTime = statbase;
    }

    ret = maxinfo;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    virBitmapFree(cpumap);
    return ret;
}

static char *
acrnDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    acrnConnectPtr privconn = domain->conn->privateData;
    virDomainObjPtr vm;
    char *ret = NULL;

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    ret = virDomainDefFormat(vm->def, privconn->xmlopt,
                             virDomainDefFormatConvertXMLFlags(flags));

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static virDomainPtr
acrnDomainCreateXML(virConnectPtr conn,
                    const char *xml,
                    unsigned int flags)
{
    acrnConnectPtr privconn = conn->privateData;
    acrnDomainObjPrivatePtr priv;
    virDomainDefPtr def;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    /* VIR_DOMAIN_START_AUTODESTROY is not supported yet */
    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, privconn->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup_nolock;

    if (!(vm = virDomainObjListAdd(privconn->domains, def,
                                   privconn->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE, NULL)))
        goto cleanup;

    priv = vm->privateData;

    def = NULL;

    if (acrnProcessPrepareDomain(vm, privconn->vcpuAllocMap) < 0)
        goto cleanup;

    if (acrnProcessStart(vm) < 0) {
        acrnFreeVcpus(priv->cpuAffinitySet, privconn->vcpuAllocMap);
        goto cleanup;
    }

    if (!(event = virDomainEventLifecycleNewFromObj(
                    vm,
                    VIR_DOMAIN_EVENT_STARTED,
                    VIR_DOMAIN_EVENT_STARTED_BOOTED))) {
        acrnProcessStop(vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

cleanup:
    if (vm) {
        if (!dom && !vm->persistent)
            /* if domain is not persistent, remove its data */
            virDomainObjListRemove(privconn->domains, vm);
        else
            virObjectUnlock(vm);
    }
    acrnDriverUnlock(privconn);
cleanup_nolock:
    virDomainDefFree(def);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return dom;
}

static int
acrnDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    acrnConnectPtr privconn = domain->conn->privateData;
    acrnDomainObjPrivatePtr priv;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    int ret = -1;

    /* VIR_DOMAIN_START_AUTODESTROY is not supported yet */
    virCheckFlags(0, -1);

    acrnDriverLock(privconn);

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain is already running"));
        goto cleanup;
    }

    priv = vm->privateData;

    if (acrnProcessPrepareDomain(vm, privconn->vcpuAllocMap) < 0)
        goto cleanup;

    if (acrnProcessStart(vm) < 0) {
        /* domain must be persistent */
        acrnFreeVcpus(priv->cpuAffinitySet, privconn->vcpuAllocMap);
        goto cleanup;
    }

    if (!(event = virDomainEventLifecycleNewFromObj(
                    vm,
                    VIR_DOMAIN_EVENT_STARTED,
                    VIR_DOMAIN_EVENT_STARTED_BOOTED))) {
        /* domain must be persistent */
        acrnProcessStop(vm, VIR_DOMAIN_SHUTOFF_DESTROYED);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    acrnDriverUnlock(privconn);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainCreate(virDomainPtr domain)
{
    return acrnDomainCreateWithFlags(domain, 0);
}

static virDomainPtr
acrnDomainDefineXMLFlags(virConnectPtr conn, const char *xml,
                         unsigned int flags)
{
    acrnConnectPtr privconn = conn->privateData;
    virDomainDefPtr def = NULL, oldDef = NULL;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    virDomainPtr dom = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if (!(def = virDomainDefParseString(xml, privconn->xmlopt,
                                        NULL, parse_flags)))
        goto cleanup_nolock;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup_nolock;

    acrnDriverLock(privconn);

    if (!(vm = virDomainObjListAdd(privconn->domains, def,
                                   privconn->xmlopt,
                                   0, &oldDef)))
        goto cleanup;

    vm->persistent = 1;

    def = NULL;

    if (virDomainDefSave(vm->newDef ? vm->newDef : vm->def,
                         privconn->xmlopt, ACRN_CONFIG_DIR) < 0)
        goto cleanup;

    if (!(event = virDomainEventLifecycleNewFromObj(
                    vm,
                    VIR_DOMAIN_EVENT_DEFINED,
                    !oldDef ?
                    VIR_DOMAIN_EVENT_DEFINED_ADDED :
                    VIR_DOMAIN_EVENT_DEFINED_UPDATED))) {
        virDomainDeleteConfig(ACRN_CONFIG_DIR,
                              ACRN_AUTOSTART_DIR,
                              vm);
        goto cleanup;
    }

    dom = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);

cleanup:
    if (vm) {
        if (!dom)
            virDomainObjListRemove(privconn->domains, vm);
        else
            virObjectUnlock(vm);
    }
    acrnDriverUnlock(privconn);
    virDomainDefFree(oldDef);
cleanup_nolock:
    virDomainDefFree(def);
    if (event)
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
    acrnConnectPtr privconn = domain->conn->privateData;
    virObjectEventPtr event = NULL;
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(domain)))
        goto cleanup;

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("cannot undefine transient domain"));
        goto cleanup;
    }

    if (virDomainDeleteConfig(ACRN_CONFIG_DIR,
                              ACRN_AUTOSTART_DIR,
                              vm) < 0)
        goto cleanup;

    event = virDomainEventLifecycleNewFromObj(
                vm,
                VIR_DOMAIN_EVENT_UNDEFINED,
                VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);

    if (virDomainObjIsActive(vm)) {
        vm->persistent = 0;
    } else {
        virDomainObjListRemove(privconn->domains, vm);
        vm = NULL;
    }

    if (!event)
        goto cleanup;

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(privconn->domainEventState, event);
    return ret;
}

static int
acrnDomainUndefine(virDomainPtr domain)
{
    return acrnDomainUndefineFlags(domain, 0);
}

static int
acrnDomainMemoryStats(virDomainPtr dom,
                      virDomainMemoryStatPtr stats,
                      unsigned int nr_stats,
                      unsigned int flags)
{
    virDomainObjPtr vm;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not active"));
        goto cleanup;
    }

    ret = 0;

    if (ret < nr_stats) {
        stats[ret].tag = VIR_DOMAIN_MEMORY_STAT_RSS;
        stats[ret].val = virDomainDefGetMemoryInitial(vm->def);
        ret++;
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
acrnDomainIsActive(virDomainPtr domain)
{
    virDomainObjPtr obj;
    int ret = -1;

    if (!(obj = acrnDomObjFromDomain(domain)))
        goto cleanup;

    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virObjectUnlock(obj);
    return ret;
}

static int
acrnDomainOpenConsole(virDomainPtr dom,
                      const char *dev_name,
                      virStreamPtr st,
                      unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainChrDefPtr chr = NULL;
    acrnDomainObjPrivatePtr priv;
    size_t i;
    int dupfd, ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain is not running"));
        goto cleanup;
    }

    if (vm->def->nserials &&
        vm->def->serials[0]->source->type == VIR_DOMAIN_CHR_TYPE_PTY)
        chr = vm->def->serials[0];
    else if (vm->def->nconsoles)
        chr = vm->def->consoles[0];

    if (!chr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find character device %s"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("character device %s is not using a PTY"),
                       dev_name ? dev_name : NULLSTR(chr->info.alias));
        goto cleanup;
    }

    priv = vm->privateData;

    for (i = 0; i < priv->nttys; i++) {
        if (priv->ttys[i].slave &&
            chr->source->data.file.path &&
            STREQ(priv->ttys[i].slave, chr->source->data.file.path))
            break;
    }

    if (i == priv->nttys) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find character device %s"),
                       NULLSTR(dev_name));
        goto cleanup;
    }

    /* dup the master's fd so it can be closed by the caller */
    if ((dupfd = dup(priv->ttys[i].fd)) < 0) {
        virReportSystemError(errno, "%s", _("dup"));
        goto cleanup;
    }

    if (virFDStreamOpen(st, dupfd) < 0) {
        VIR_FORCE_CLOSE(dupfd);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
acrnGetDomainTotalCpuStats(virTypedParameterPtr params,
                           int nparams)
{
    struct timeval tv;
    unsigned long long cpu_time;

    if (nparams == 0) /* return supported number of params */
        return 1;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        return -1;
    }

    /* FIXME fake an increasing cpu time value */
    cpu_time = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;

    /* entry 0 is cputime */
    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_CPU_STATS_CPUTIME,
                                VIR_TYPED_PARAM_ULLONG, cpu_time) < 0)
        return -1;

    if (nparams > 1)
        nparams = 1;

    return nparams;
}

static int
acrnGetPercpuStats(virTypedParameterPtr params,
                   unsigned int nparams,
                   int start_cpu,
                   unsigned int ncpus,
                   virBitmapPtr vcpus)
{
    int ret = -1;
    size_t i;
    int total_cpus, param_idx, need_cpus;
    struct timeval tv;
    unsigned long long cpu_time;
    virBitmapPtr cpumap;
    virTypedParameterPtr ent;

    /* return the number of supported params */
    if (nparams == 0 && ncpus != 0)
        return 1;

    if (!(cpumap = virHostCPUGetPresentBitmap()))
        goto cleanup;

    total_cpus = virBitmapSize(cpumap);

    /* return total number of cpus */
    if (ncpus == 0) {
        ret = total_cpus;
        goto cleanup;
    }

    if (start_cpu >= total_cpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("start_cpu %d larger than maximum of %d"),
                       start_cpu, total_cpus - 1);
        goto cleanup;
    }

    if (!vcpus) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("cpumask missing"));
        goto cleanup;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        goto cleanup;
    }

    /* FIXME fake an increasing cpu time value */
    cpu_time = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;
    cpu_time /= virBitmapCountBits(vcpus);

    /* return percpu cputime in index 0 */
    param_idx = 0;

    /* number of cpus to compute */
    need_cpus = MIN(total_cpus, start_cpu + ncpus);

    for (i = start_cpu; i < need_cpus; i++) {
        ent = &params[(i - start_cpu) * nparams + param_idx];
        if (virTypedParameterAssign(ent, VIR_DOMAIN_CPU_STATS_CPUTIME,
                                    VIR_TYPED_PARAM_ULLONG,
                                    virBitmapIsBitSet(vcpus, i) ?
                                    cpu_time : 0) < 0)
            goto cleanup;
    }

    param_idx++;
    ret = param_idx;

cleanup:
    virBitmapFree(cpumap);
    return ret;
}

static int
acrnDomainGetCPUStats(virDomainPtr dom,
                      virTypedParameterPtr params,
                      unsigned int nparams,
                      int start_cpu,
                      unsigned int ncpus,
                      unsigned int flags)
{
    virDomainObjPtr vm;
    acrnDomainObjPrivatePtr priv;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = acrnDomObjFromDomain(dom)))
        goto cleanup;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("domain is not running"));
        goto cleanup;
    }

    if (start_cpu == -1) {
        ret = acrnGetDomainTotalCpuStats(params, nparams);
    } else {
        priv = vm->privateData;
        ret = acrnGetPercpuStats(params, nparams, start_cpu, ncpus,
                                 priv->cpuAffinitySet);
    }

cleanup:
    if (vm)
        virObjectUnlock(vm);
    return ret;
}

static int
acrnConnectURIProbe(char **uri)
{
    if (!acrn_driver)
        return 0;

    *uri = g_strdup("acrn:///system");
    return 1;
}

static virDrvOpenStatus
acrnConnectOpen(virConnectPtr conn,
                virConnectAuthPtr auth G_GNUC_UNUSED,
                virConfPtr conf G_GNUC_UNUSED,
                unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->uri->path, "/system")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected ACRN URI path '%s', try acrn:///system"),
                       conn->uri->path);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!acrn_driver) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("ACRN state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
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

static const char *
acrnConnectGetType(virConnectPtr conn G_GNUC_UNUSED)
{
    return "ACRN";
}

static int
acrnConnectGetVersion(virConnectPtr conn G_GNUC_UNUSED,
                      unsigned long *version)
{
    virCommandPtr cmd;
    char *verstr = NULL;
    const char *dmstr = "DM version is: ";
    int ret = -1;

    if (!(cmd = virCommandNewArgList(ACRN_DM_PATH, "-v", NULL))) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }

    virCommandSetOutputBuffer(cmd, &verstr);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (!(dmstr = STRSKIP(verstr, dmstr)))
        goto cleanup;

    if (virParseVersionString(dmstr, version, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown release: %s"), dmstr);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (verstr)
        VIR_FREE(verstr);
    virCommandFree(cmd);
    return ret;
}

static char *
acrnConnectGetHostname(virConnectPtr conn G_GNUC_UNUSED)
{
    return virGetHostname();
}

static char *
acrnConnectGetCapabilities(virConnectPtr conn)
{
    acrnConnectPtr privconn = conn->privateData;
    virCapsPtr caps;
    char *xml;

    if (!(caps = acrnDriverGetCapabilities(privconn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to get capabilities"));
        return NULL;
    }

    xml = virCapabilitiesFormatXML(caps);
    virObjectUnref(caps);
    return xml;
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

static char *
acrnConnectBaselineCPU(virConnectPtr conn G_GNUC_UNUSED,
                       const char **xmlCPUs,
                       unsigned int ncpus,
                       unsigned int flags)
{
    virCPUDefPtr *cpus;
    virCPUDefPtr cpu = NULL;
    char *cpustr = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (!(cpus = virCPUDefListParse(xmlCPUs, ncpus, VIR_CPU_TYPE_HOST)))
        goto cleanup;

    if (!(cpu =
            virCPUBaseline(VIR_ARCH_NONE, cpus, ncpus, NULL, NULL,
                           !!(flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE))))
        goto cleanup;

    if ((flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) &&
        virCPUExpandFeatures(cpus[0]->arch, cpu) < 0)
        goto cleanup;

    cpustr = virCPUDefFormat(cpu, NULL);

cleanup:
    virCPUDefFree(cpu);
    virCPUDefListFree(cpus);
    return cpustr;
}

static int
acrnConnectDomainEventRegisterAny(virConnectPtr conn,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback callback,
                                  void *opaque,
                                  virFreeCallback freecb)
{
    acrnConnectPtr privconn = conn->privateData;
    int ret;

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
    acrnConnectPtr privconn = conn->privateData;

    if (virObjectEventStateDeregisterID(conn,
                                        privconn->domainEventState,
                                        callbackID, true) < 0)
        return -1;

    return 0;
}

static int
acrnNodeGetInfo(virConnectPtr conn,
                virNodeInfoPtr info)
{
    acrnConnectPtr privconn = conn->privateData;

    memcpy(info, &privconn->nodeInfo, sizeof(*info));
    return 0;
}

static int
acrnNodeDeviceGetPCIInfo(virNodeDeviceDefPtr def,
                         unsigned *domain,
                         unsigned *bus,
                         unsigned *slot,
                         unsigned *function)
{
    virNodeDevCapsDefPtr cap = def->caps;

    while (cap) {
        if (cap->data.type == VIR_NODE_DEV_CAP_PCI_DEV) {
            *domain   = cap->data.pci_dev.domain;
            *bus      = cap->data.pci_dev.bus;
            *slot     = cap->data.pci_dev.slot;
            *function = cap->data.pci_dev.function;
            break;
        }

        cap = cap->next;
    }

    if (!cap) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device %s is not a PCI device"), def->name);
        return -1;
    }

    return 0;
}

static int
acrnNodeDeviceDetachFlags(virNodeDevicePtr dev,
                          const char *driverName,
                          unsigned int flags)
{
    char *xml;
    virNodeDeviceDefPtr def = NULL;
    virPCIDevicePtr pci = NULL;
    acrnConnectPtr privconn = dev->conn->privateData;
    virHostdevManagerPtr hostdev_mgr = privconn->hostdevMgr;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(xml = virNodeDeviceGetXMLDesc(dev, 0)))
        goto cleanup;

    if (!(def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL)))
        goto cleanup;

    if (acrnNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    if (!(pci = virPCIDeviceNew(domain, bus, slot, function)))
        goto cleanup;

    /* use the pci-stub driver */
    if (!driverName || STREQ(driverName, "kvm")) {
        virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_KVM);
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported driver name '%s'"), driverName);
        goto cleanup;
    }

    if (virHostdevPCINodeDeviceDetach(hostdev_mgr, pci) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virPCIDeviceFree(pci);
    virNodeDeviceDefFree(def);
    if (xml)
        VIR_FREE(xml);
    return ret;
}

static int
acrnNodeDeviceDettach(virNodeDevicePtr dev)
{
    return acrnNodeDeviceDetachFlags(dev, NULL, 0);
}

static int
acrnNodeDeviceReAttach(virNodeDevicePtr dev)
{
    char *xml;
    virNodeDeviceDefPtr def = NULL;
    virPCIDevicePtr pci = NULL;
    acrnConnectPtr privconn = dev->conn->privateData;
    virHostdevManagerPtr hostdev_mgr = privconn->hostdevMgr;
    unsigned domain = 0, bus = 0, slot = 0, function = 0;
    int ret = -1;

    if (!(xml = virNodeDeviceGetXMLDesc(dev, 0)))
        goto cleanup;

    if (!(def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL)))
        goto cleanup;

    if (acrnNodeDeviceGetPCIInfo(def, &domain, &bus, &slot, &function) < 0)
        goto cleanup;

    if (!(pci = virPCIDeviceNew(domain, bus, slot, function)))
        goto cleanup;

    if (virHostdevPCINodeDeviceReAttach(hostdev_mgr, pci) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virPCIDeviceFree(pci);
    virNodeDeviceDefFree(def);
    if (xml)
        VIR_FREE(xml);
    return ret;
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
acrnStateCleanup(void)
{
    VIR_DEBUG("ACRN state cleanup");

    if (!acrn_driver)
        return -1;

    virObjectUnref(acrn_driver->hostdevMgr);
    virObjectUnref(acrn_driver->domainEventState);
    virObjectUnref(acrn_driver->xmlopt);
    virObjectUnref(acrn_driver->caps);
    virObjectUnref(acrn_driver->domains);

    if (acrn_driver->vcpuAllocMap)
        VIR_FREE(acrn_driver->vcpuAllocMap);
    virMutexDestroy(&acrn_driver->lock);
    VIR_FREE(acrn_driver);

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

#if 0
    if (virCapabilitiesSetNetPrefix(caps, ACRN_NET_GENERATED_TAP_PREFIX) < 0) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        goto error;
    }
#endif

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        goto error;

    if (virCapabilitiesInitCaches(caps) < 0)
        VIR_WARN("Failed to get host CPU cache info");

    if (!(caps->host.cpu = virCPUProbeHost(caps->host.arch)))
        VIR_WARN("Failed to get host CPU");

    /* add the power management features of the host */
    if (virNodeSuspendGetTargetMask(&caps->host.powerMgmt) < 0)
        VIR_WARN("Failed to get host power management capabilities");

    /* add huge pages info */
    if (virCapabilitiesInitPages(caps) < 0)
        VIR_WARN("Failed to get pages info");

    return caps;

error:
    virObjectUnref(caps);
    return NULL;
}

/*
 * Vacate SOS CPUs for UOS vCPU allocation.
 */
static int
acrnOfflineCpus(int nprocs)
{
    ssize_t i = -1;
    int fd;
    char path[128], chr, online, cpu_id[4];
    ssize_t rc;
    virBitmapPtr cpus;

    cpus = virHostCPUGetOnlineBitmap();
    while ((i = virBitmapNextSetBit(cpus, i)) >= 0 && i < nprocs) {
        /* cpu0 can't be offlined */
        if (i == 0)
            continue;

        snprintf(cpu_id, sizeof(cpu_id), "%ld", i);
        snprintf(path, sizeof(path), "%s/cpu%s/online", SYSFS_CPU_PATH, cpu_id);

        if ((fd = open(path, O_RDWR)) < 0) {
            virReportError(VIR_ERR_OPEN_FAILED, _("%s"), path);
            return -1;
        }

        chr = '0';

        do {
            if (pwrite(fd, &chr, sizeof(chr), 0) < sizeof(chr)) {
                close(fd);
                virReportError(VIR_ERR_WRITE_FAILED, _("%s"), path);
                return -1;
            }
        } while ((rc = pread(fd, &online, sizeof(online), 0)) > 0 &&
                 online != '0');

        close(fd);

        if (rc <= 0) {
            virReportError(VIR_ERR_READ_FAILED, _("%s"), path);
            return -1;
        }

        if ((fd = open(ACRN_OFFLINE_PATH, O_WRONLY)) < 0) {
            virReportError(VIR_ERR_OPEN_FAILED, _(ACRN_OFFLINE_PATH));
            return -1;
        }

        if (write(fd, cpu_id, strlen(cpu_id)) < strlen(cpu_id)) {
            close(fd);
            virReportError(VIR_ERR_WRITE_FAILED, _(ACRN_OFFLINE_PATH));
            return -1;
        }

        close(fd);
    }

    return 0;
}

static int
acrnInitPlatform(virNodeInfoPtr nodeInfo, size_t **allocMap)
{
    uint16_t totalCpus;
    size_t *map = NULL;
    int ret;

    totalCpus = get_nprocs_conf();

    if (VIR_ALLOC_N(map, totalCpus) < 0) {
        ret = -ENOMEM;
        goto cleanup;
    }

    nodeInfo->cpus = totalCpus;

    if (acrnOfflineCpus(nodeInfo->cpus) < 0) {
        ret = -EIO;
        goto cleanup;
    }

    *allocMap = map;
    map = NULL;
    ret = 0;

cleanup:
    if (map)
        VIR_FREE(map);
    return ret;
}

static int
acrnPersistentDomainInit(virDomainObjPtr dom, void *opaque)
{
    virObjectEventPtr event = NULL;
    acrnConnectPtr driver = opaque;

    if (!dom->persistent)
        return 0;

    event = virDomainEventLifecycleNewFromObj(dom,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              VIR_DOMAIN_EVENT_DEFINED_ADDED);
    if (!event)
        return -1;

    virObjectEventStateQueue(driver->domainEventState, event);
    return 0;
}
struct acrnProcessReconnectData {
    acrnConnectPtr driver;
};
static int
viracrnProcessReconnect(virDomainObjPtr vm,
                         void *opaque)
{
    int ret = -1;

    if (!virDomainObjIsActive(vm))
        return 0;
    VIR_DEBUG("ACRN driver try to reconnect %s\n", vm->def->name);

    if (acrnProcessWaitForMonitor(vm, &acrnProcessStopCallback) < 0)
        goto cleanup;
    ret = 0;
cleanup:
    return ret;
}
static void
viracrnProcessReconnectAll(acrnConnectPtr driver)
{
    struct acrnProcessReconnectData data;
    data.driver = driver;
    virDomainObjListForEach(driver->domains, false, viracrnProcessReconnect, &data);
    return;
}
static virDrvStateInitResult
acrnStateInitialize(bool privileged,
                    const char *root,
                    virStateInhibitCallback callback G_GNUC_UNUSED,
                    void *opaque G_GNUC_UNUSED)
{
    int ret;
    bool autostart = true;

    if (root) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return VIR_DRV_STATE_INIT_ERROR;
    }

    if (!privileged) {
        VIR_INFO("Not running privileged, disabling driver");
        return VIR_DRV_STATE_INIT_SKIPPED;
    }

    if (VIR_ALLOC(acrn_driver) < 0)
        return VIR_DRV_STATE_INIT_ERROR;

    if (virMutexInit(&acrn_driver->lock) < 0) {
        VIR_FREE(acrn_driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    /* store a copy of node info before CPU offlining */
    if (virCapabilitiesGetNodeInfo(&acrn_driver->nodeInfo) < 0)
        goto cleanup;


    if (acrnInitPlatform(&acrn_driver->nodeInfo,
                         &acrn_driver->vcpuAllocMap) < 0)
        goto cleanup;

    if (!(acrn_driver->domains = virDomainObjListNew()))
        goto cleanup;

    if (!(acrn_driver->caps = virAcrnCapsBuild()))
        goto cleanup;

    if (!(acrn_driver->xmlopt = virAcrnDriverCreateXMLConf()))
        goto cleanup;

    if (!(acrn_driver->domainEventState = virObjectEventStateNew()))
        goto cleanup;

    if (!(acrn_driver->hostdevMgr = virHostdevManagerGetDefault()))
        goto cleanup;

    if (virFileMakePath(ACRN_STATE_DIR) < 0) {
	    virReportSystemError(errno,
			                _("Failed to mkdir %s"),
			                ACRN_STATE_DIR);
	    goto cleanup;
    }
    if (virFileMakePath(ACRN_MONITOR_DIR) < 0) {
	    virReportSystemError(errno,
			                _("Failed to mkdir %s"),
			                ACRN_MONITOR_DIR);
	    goto cleanup;
    }

    if (virDomainObjListLoadAllConfigs(acrn_driver->domains,
                                       ACRN_STATE_DIR,
                                       NULL, true,
                                       acrn_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;
    /* load inactive persistent configs */
    if (virDomainObjListLoadAllConfigs(acrn_driver->domains,
                                       ACRN_CONFIG_DIR,
                                       ACRN_AUTOSTART_DIR, false,
                                       acrn_driver->xmlopt,
                                       NULL, NULL) < 0)
        goto cleanup;

    if (virDomainObjListForEach(acrn_driver->domains, false,
                                acrnPersistentDomainInit, acrn_driver) < 0)
        goto cleanup;

    viracrnProcessReconnectAll(acrn_driver);

    if (virDriverShouldAutostart(ACRN_STATE_DIR, &autostart) < 0)
        goto cleanup;

    if (autostart)
        acrnAutostartDomains(acrn_driver);

    return VIR_DRV_STATE_INIT_COMPLETE;

cleanup:
    ret = VIR_DRV_STATE_INIT_ERROR;
    acrnStateCleanup();
    return ret;
}

static virHypervisorDriver acrnHypervisorDriver = {
    .name = "ACRN",
    .connectURIProbe = acrnConnectURIProbe, /* 0.0.1 */
    .connectOpen = acrnConnectOpen, /* 0.0.1 */
    .connectClose = acrnConnectClose, /* 0.0.1 */
    .connectGetType = acrnConnectGetType, /* 0.0.1 */
    .connectGetVersion = acrnConnectGetVersion, /* 0.0.1 */
    .connectGetHostname = acrnConnectGetHostname, /* 0.0.1 */
    .nodeGetInfo = acrnNodeGetInfo, /* 0.0.1 */
    .connectGetCapabilities = acrnConnectGetCapabilities, /* 0.0.1 */
    .connectListAllDomains = acrnConnectListAllDomains, /* 0.0.1 */
    .domainCreateXML = acrnDomainCreateXML, /* 0.0.1 */
    .domainLookupByUUID = acrnDomainLookupByUUID, /* 0.0.1 */
    .domainLookupByName = acrnDomainLookupByName, /* 0.0.1 */
    .domainShutdown = acrnDomainShutdown, /* 0.0.1 */
    .domainDestroy = acrnDomainDestroy, /* 0.0.1 */
    .domainIsPersistent = acrnDomainIsPersistent, /* 0.0.1 */
    .domainGetAutostart = acrnDomainGetAutostart, /* 0.0.1 */
    .domainSetAutostart = acrnDomainSetAutostart, /* 0.0.1 */
    .domainGetInfo = acrnDomainGetInfo,  /* 0.0.1 */
    .domainGetState = acrnDomainGetState, /* 0.0.1 */
    .domainGetVcpus = acrnDomainGetVcpus, /* 0.0.1 */
    .domainGetXMLDesc = acrnDomainGetXMLDesc, /* 0.0.1 */
    .domainCreate = acrnDomainCreate, /* 0.0.1 */
    .domainCreateWithFlags = acrnDomainCreateWithFlags, /* 0.0.1 */
    .domainDefineXML = acrnDomainDefineXML, /* 0.0.1 */
    .domainDefineXMLFlags = acrnDomainDefineXMLFlags, /* 0.0.1 */
    .domainUndefine = acrnDomainUndefine, /* 0.0.1 */
    .domainUndefineFlags = acrnDomainUndefineFlags, /* 0.0.1 */
    .domainMemoryStats = acrnDomainMemoryStats, /* 0.0.1 */
    .nodeDeviceDettach = acrnNodeDeviceDettach, /* 0.0.1 */
    .nodeDeviceDetachFlags = acrnNodeDeviceDetachFlags, /* 0.0.1 */
    .nodeDeviceReAttach = acrnNodeDeviceReAttach, /* 0.0.1 */
    .domainIsActive = acrnDomainIsActive, /* 0.0.1 */
    .connectBaselineCPU = acrnConnectBaselineCPU, /* 0.0.1 */
    .connectDomainEventRegisterAny = acrnConnectDomainEventRegisterAny, /* 0.0.1 */
    .connectDomainEventDeregisterAny = acrnConnectDomainEventDeregisterAny, /* 0.0.1 */
    .domainOpenConsole = acrnDomainOpenConsole, /* 0.0.1 */
    .domainGetCPUStats = acrnDomainGetCPUStats, /* 0.0.1 */
    .nodeGetCPUMap = acrnNodeGetCPUMap, /* 0.0.1 */
};

static virConnectDriver acrnConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "acrn", NULL },
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
