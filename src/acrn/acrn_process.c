/*
 * acrn_process.c: acrn process management
 * Adapted from bhyve_process.c. Original license and copyright:
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 *
 */

#include <config.h>

#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/user.h>

#include "acrn_device.h"
#include "acrn_driver.h"
#include "acrn_command.h"
#include "acrn_domain.h"
#include "acrn_firmware.h"
#include "acrn_monitor.h"
#include "acrn_process.h"
#include "datatypes.h"
#include "virerror.h"
#include "virhook.h"
#include "virlog.h"
#include "virfile.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virstring.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"

#define VIR_FROM_THIS   VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_process");

static void
acrnProcessAutoDestroy(virDomainObj *vm,
                        virConnectPtr conn G_GNUC_UNUSED)
{
    acrnDomainObjPrivate *priv = vm->privateData;
    struct _acrnConn *driver = priv->driver;

    virAcrnProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_DESTROYED);

    virAcrnDomainRemoveInactive(driver, vm);
}

static void
acrnNetCleanup(virDomainObj *vm)
{
    size_t i;

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDef *net = vm->def->nets[i];
        virDomainNetType actualType = virDomainNetGetActualType(net);

        if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (net->ifname) {
                ignore_value(virNetDevBridgeRemovePort(
                                virDomainNetGetActualBridgeName(net),
                                net->ifname));
                ignore_value(virNetDevTapDelete(net->ifname, NULL));
            }
        }
    }
}

static int
acrnProcessStartHook(struct _acrnConn *driver,
                      virDomainObj *vm,
                      virHookAcrnOpType op)
{
    g_autofree char *xml = NULL;

    if (!virHookPresent(VIR_HOOK_DRIVER_ACRN))
        return 0;

    xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

    return virHookCall(VIR_HOOK_DRIVER_ACRN, vm->def->name, op,
                       VIR_HOOK_SUBOP_BEGIN, NULL, xml, NULL);
}

static void
acrnProcessStopHook(struct _acrnConn *driver,
                     virDomainObj *vm,
                     virHookAcrnOpType op)
{
    g_autofree char *xml = NULL;
    if (!virHookPresent(VIR_HOOK_DRIVER_ACRN))
        return;

    xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

    virHookCall(VIR_HOOK_DRIVER_ACRN, vm->def->name, op,
                VIR_HOOK_SUBOP_END, NULL, xml, NULL);
}

static int
virAcrnProcessStartImpl(struct _acrnConn *driver,
                         virDomainObj *vm,
                         virDomainRunningReason reason)
{
    g_autofree char *devmap_file = NULL;
    g_autofree char *devicemap = NULL;
    g_autofree char *logfile = NULL;
    VIR_AUTOCLOSE logfd = -1;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virCommand) load_cmd = NULL;
    acrnDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    logfile = g_strdup_printf("%s/%s.log", ACRN_LOG_DIR, vm->def->name);
    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
                      S_IRUSR | S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%1$s'"),
                             logfile);
        goto cleanup;
    }

    VIR_FREE(driver->pidfile);
    if (!(driver->pidfile = virPidFileBuildPath(ACRN_STATE_DIR,
                                                vm->def->name))) {
        virReportSystemError(errno,
                             "%s", _("Failed to build pidfile path"));
        goto cleanup;
    }

    if (unlink(driver->pidfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot remove stale PID file %1$s"),
                             driver->pidfile);
        goto cleanup;
    }

    if (acrnDomainAssignAddresses(vm->def, NULL) < 0)
        goto cleanup;

    /* Call acrn to start the VM */
    if (!(cmd = virAcrnProcessBuildAcrnCmd(driver, vm->def, false)))
        goto cleanup;

    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);
    virCommandWriteArgLog(cmd, logfd);
    virCommandSetPidFile(cmd, driver->pidfile);
    virCommandDaemonize(cmd);

    if (acrnProcessStartHook(driver, vm, VIR_HOOK_ACRN_OP_START) < 0)
        goto cleanup;

    /* Now we can start the domain */
    VIR_DEBUG("Starting domain '%s'", vm->def->name);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (virPidFileReadPath(driver->pidfile, &vm->pid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Domain %1$s didn't show up"), vm->def->name);
        goto cleanup;
    }

    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
    priv->mon = acrnMonitorOpen(vm, driver);

    if (virDomainObjSave(vm, driver->xmlopt,
                         ACRN_STATE_DIR) < 0)
        goto cleanup;

    if (acrnProcessStartHook(driver, vm, VIR_HOOK_ACRN_OP_STARTED) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0) {
        int exitstatus; /* Needed to avoid logging non-zero status */
        g_autoptr(virCommand) destroy_cmd = NULL;
        if ((destroy_cmd = virAcrnProcessBuildDestroyCmd(driver,
                                                          vm->def)) != NULL) {
            virCommandSetOutputFD(load_cmd, &logfd);
            virCommandSetErrorFD(load_cmd, &logfd);
            ignore_value(virCommandRun(destroy_cmd, &exitstatus));
        }

        acrnNetCleanup(vm);
    }

    return ret;
}

static void
acrnOfflineSingleCPU(int cpu)
{
#define ACRN_CPU_OFFLINE_PATH       "/sys/devices/virtual/misc/acrn_hsm/remove_cpu"
#define SYSFS_CPU_OFFLINE_PATH      "/sys/devices/system/cpu"
    char *path, *content;

    VIR_INFO("Offlining cpu%d from Service OS", cpu);
    path = g_strdup_printf("%s/cpu%d/online", SYSFS_CPU_OFFLINE_PATH, cpu);
    if (virFileWriteStr(path, "0", 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "Failed to offline cpu%d from Service OS", cpu);
        goto out;
    }

    VIR_INFO("Offlining vcpu%d from Service VM", cpu);
    content = g_strdup_printf("%d", cpu);
    if (virFileWriteStr(ACRN_CPU_OFFLINE_PATH, content, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "Failed to offline vcpu%d from Service VM", cpu);
    }

    VIR_FREE(content);
out:
    VIR_FREE(path);
}

static int
acrnOfflineCPUs(acrnConn *driver G_GNUC_UNUSED, virDomainObj *vm)
{
    g_autoptr(virBitmap) online = NULL;
    g_autoptr(virBitmap) cpumask = NULL;
    ssize_t i = -1;

    online = virHostCPUGetOnlineBitmap();
    if (online == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "failed to get host online cpu bitmap");
        return -1;
    }

    cpumask = virBitmapNewCopy(vm->def->cpumask);
    /* cpumask -= online */
    virBitmapSubtract(cpumask, online);

    while ((i = virBitmapNextSetBit(cpumask, i)) != -1) {
        /* cpu0 cannot be offlined */
        if (i > 0)
            acrnOfflineSingleCPU(i);
    }

    return 0;
}

static bool
acrnVMIsLapicPT(virDomainObj *vm G_GNUC_UNUSED)
{
    /* FIXME: To be implemented
     *
     * We need to be careful when specifying lapic pt,
     * as /proc/cpuinfo will no longer contain APIC ID
     * of CPUs that are offlined.
     *
     * We will read /proc/cpuinfo upon daemon initialization
     * and record all APIC IDs in an array (acrnGetApicIDs).
     * This means that we MUST have all CPUs online when
     * we run libvirt acrn daemon.
     */
    return false;
}

static int
acrnHostdevPrepareDomainDevices(acrnConn *driver, virDomainDef *def, unsigned int flags)
{
    ssize_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];
        virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;

        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            pcisrc->driver.name == VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_DEFAULT) {
            pcisrc->driver.name = VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_KVM;
        }

    }

    /* Currently we prepare only PCI device */
    return virHostdevPreparePCIDevices(driver->hostdevMgr, "acrn",
            def->name, def->uuid, def->hostdevs, def->nhostdevs, flags);
}

static void
acrnHostdevReAttachDomainDevices(acrnConn *driver,
                                 const char *name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs)
{
    virHostdevReAttachPCIDevices(driver->hostdevMgr, "acrn", name, hostdevs, nhostdevs);
}

static void
acrnCleanupConsoleTty(virDomainObj *vm)
{
    ssize_t i;
    acrnDomainObjPrivate *priv = vm->privateData;

    for (i = 0; i < vm->def->nserials; i++) {
        VIR_FORCE_CLOSE(priv->ttyfds[i]);
    }

    VIR_FREE(priv->ttyfds);
}

static int
acrnPrepareConsoleTty(virDomainObj *vm)
{
    ssize_t i;
    char *ttyPath = NULL;
    acrnDomainObjPrivate *priv = vm->privateData;

    if (!vm->def->nserials)
        return 0;

    if (priv->ttyfds == NULL) {
        priv->ttyfds = g_new(int, vm->def->nserials);
        for (i = 0; i < vm->def->nserials; i++)
            priv->ttyfds[i] = -1;
    }

    for (i = 0; i < vm->def->nserials; i++) {
        if (virFileOpenTty(&priv->ttyfds[i], &ttyPath, 1) < 0) {
            virReportSystemError(errno, "%s", "failed to allocate tty");
            goto cleanup;
        }

        VIR_INFO("TTY %s opened", ttyPath);
        VIR_FREE(vm->def->serials[i]->source->data.file.path);
        vm->def->serials[i]->source->data.file.path = g_strdup(ttyPath);
    }

    VIR_FREE(ttyPath);
    return 0;

cleanup:
    acrnCleanupConsoleTty(vm);
    VIR_FREE(ttyPath);

    return -1;
}

int
acrnProcessPrepareDomain(acrnConn *driver,
                          virDomainObj *vm,
                          unsigned int flags G_GNUC_UNUSED)
{
    int ret = 0;

    if (acrnVMIsLapicPT(vm)) {
        ret = acrnOfflineCPUs(driver, vm);
    }

    if (acrnHostdevPrepareDomainDevices(driver, vm->def, 0) < 0)
        ret = -1;

    if (acrnPrepareConsoleTty(vm) < 0)
        ret = -1;

    return ret;
}

int
virAcrnProcessStart(virConnectPtr conn,
                     virDomainObj *vm,
                     virDomainRunningReason reason,
                     unsigned int flags)
{
    struct _acrnConn *driver = conn->privateData;

    /* Run an early hook to setup missing devices. */
    if (acrnProcessStartHook(driver, vm, VIR_HOOK_ACRN_OP_PREPARE) < 0)
        return -1;

    if (flags & VIR_ACRN_PROCESS_START_AUTODESTROY)
        virCloseCallbacksDomainAdd(vm, conn, acrnProcessAutoDestroy);

    if (acrnProcessPrepareDomain(driver, vm, flags) < 0)
        return -1;

    return virAcrnProcessStartImpl(driver, vm, reason);
}

int
virAcrnProcessStop(struct _acrnConn *driver,
                    virDomainObj *vm,
                    virDomainShutoffReason reason)
{
    int ret = -1;
    g_autoptr(virCommand) cmd = NULL;
    acrnDomainObjPrivate *priv = vm->privateData;

    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        return 0;
    }

    if (vm->pid == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid PID %1$d for VM"),
                       (int)vm->pid);
        return -1;
    }

    if (reason != VIR_DOMAIN_SHUTOFF_SHUTDOWN) {
        /* VIR_DOMAIN_SHUTOFF_SHUTDOWN means guest shut itself down. */
        virAcrnProcessShutdown(vm);
    }

    if ((priv != NULL) && (priv->mon != NULL))
         acrnMonitorClose(priv->mon);

    acrnProcessStopHook(driver, vm, VIR_HOOK_ACRN_OP_STOPPED);

    /* Cleanup network interfaces */
    acrnNetCleanup(vm);

    /* VNC autoport cleanup */
    if ((vm->def->ngraphics == 1) &&
        vm->def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        if (virPortAllocatorRelease(vm->def->graphics[0]->data.vnc.port) < 0) {
            VIR_WARN("Failed to release VNC port for '%s'",
                     vm->def->name);
        }
    }

    /* Passthrough device re-attach */
    acrnHostdevReAttachDomainDevices(driver, vm->def->name, vm->def->hostdevs,
            vm->def->nhostdevs);

    acrnCleanupConsoleTty(vm);

    ret = 0;

    virCloseCallbacksDomainRemove(vm, NULL, acrnProcessAutoDestroy);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = 0;
    vm->def->id = -1;

    acrnProcessStopHook(driver, vm, VIR_HOOK_ACRN_OP_RELEASE);

    virPidFileDelete(ACRN_STATE_DIR, vm->def->name);
    virDomainDeleteConfig(ACRN_STATE_DIR, NULL, vm);

    return ret;
}

int
virAcrnProcessShutdown(virDomainObj *vm)
{
    if (vm->pid == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid PID %1$d for VM"),
                       (int)vm->pid);
        return -1;
    }

    /* ACRN handles SIGTERM and exits gracefully */
    if (virProcessKill(vm->pid, SIGTERM) != 0) {
        VIR_WARN("Failed to terminate acrn process for VM '%s': %s",
                 vm->def->name, virGetLastErrorMessage());
        return -1;
    }

    return 0;
}

int
virAcrnProcessRestart(struct _acrnConn *driver,
                       virDomainObj *vm)
{
    if (virAcrnProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN) < 0)
        return -1;

    if (virAcrnProcessStartImpl(driver, vm, VIR_DOMAIN_RUNNING_BOOTED) < 0)
        return -1;

    return 0;
}

int
virAcrnGetDomainTotalCpuStats(virDomainObj *vm,
                               unsigned long long *cpustats)
{
#if 0
    struct kinfo_proc *kp;
    kvm_t *kd;
    g_autofree char *errbuf = g_new0(char, _POSIX2_LINE_MAX);
    int nprocs;
    int ret = -1;

    if ((kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf)) == NULL) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to get kvm descriptor: %1$s"),
                       errbuf);
        return -1;

    }

    kp = kvm_getprocs(kd, KERN_PROC_PID, vm->pid, &nprocs);
    if (kp == NULL || nprocs != 1) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to obtain information about pid: %1$d"),
                       (int)vm->pid);
        goto cleanup;
    }

    *cpustats = kp->ki_runtime * 1000ull;

    ret = 0;

 cleanup:
    kvm_close(kd);

    return ret;
#endif
    (void)vm;
    (void)cpustats;
    return -1;
}

struct acrnProcessReconnectData {
    struct _acrnConn *driver;
};

static int
virAcrnProcessReconnect(virDomainObj *vm,
                         void *opaque)
{
    struct acrnProcessReconnectData *data = opaque;
    acrnDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    if (!virDomainObjIsActive(vm))
        return 0;

    if (vm->pid == 0)
        return 0;

    virObjectLock(vm);

    priv->mon = acrnMonitorOpen(vm, data->driver);
    if (!priv->mon) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    if (ret < 0) {
        /* If VM is reported to be in active state, but we cannot find
         * its PID, then we clear information about the PID and
         * set state to 'shutdown' */
        vm->pid = 0;
        vm->def->id = -1;
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_UNKNOWN);
        ignore_value(virDomainObjSave(vm, data->driver->xmlopt,
                                      ACRN_STATE_DIR));
        virAcrnDomainRemoveInactive(data->driver, vm);
    }

    virObjectUnlock(vm);

    return ret;
}

void
virAcrnProcessReconnectAll(struct _acrnConn *driver)
{
    struct acrnProcessReconnectData data;
    data.driver = driver;
    virDomainObjListForEach(driver->domains, false, virAcrnProcessReconnect, &data);
}
