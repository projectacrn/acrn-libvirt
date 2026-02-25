/*
 * acrn_monitor.c: Tear-down or reboot acrn domains on guest shutdown
 * Adapted from bhyve_monitor.c. Original license and copyright:
 *
 * Copyright (C) 2014 Conrad Meyer
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "acrn_domain.h"
#include "acrn_monitor.h"
#include "acrn_process.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"

#define VIR_FROM_THIS   VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_monitor");

struct _acrnMonitor {
    virObject parent;

    struct _acrnConn *driver;
    virDomainObj *vm;
    int fd;
    int watch;
    bool reboot;
};

static virClass *acrnMonitorClass;

static void
acrnMonitorDispose(void *obj)
{
    acrnMonitor *mon = obj;

    VIR_FORCE_CLOSE(mon->fd);
    virObjectUnref(mon->vm);
}

static int
acrnMonitorOnceInit(void)
{
    if (!VIR_CLASS_NEW(acrnMonitor, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(acrnMonitor);

static void acrnMonitorIO(int, int, int, void *);

static bool
acrnMonitorRegister(acrnMonitor *mon)
{
    virObjectRef(mon);
    mon->watch = virEventAddHandle(mon->fd,
                                   VIR_EVENT_HANDLE_READABLE |
                                   VIR_EVENT_HANDLE_HANGUP,
                                   acrnMonitorIO,
                                   mon,
                                   virObjectUnref);
    if (mon->watch < 0) {
        VIR_DEBUG("failed to add event handle for mon %p", mon);
        virObjectUnref(mon);
        return false;
    }
    return true;
}

static void
acrnMonitorUnregister(acrnMonitor *mon)
{
    if (mon->watch < 0)
        return;

    virEventRemoveHandle(mon->watch);
    mon->watch = -1;
}

void
acrnMonitorSetReboot(acrnMonitor *mon)
{
    mon->reboot = true;
}

static void
acrnMonitorIO(int watch, int fd, int events, void *opaque)
{
    acrnMonitor *mon = opaque;
    virDomainObj *vm = mon->vm;
    struct _acrnConn *driver = mon->driver;

    if (watch != mon->watch || fd != mon->fd) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("event from unexpected fd %1$d!=%2$d / watch %3$d!=%4$d"),
                       mon->fd, fd, mon->watch, watch);
        return;
    }

    /* pidfd exists on kernel >= 5.3 and waitid on pidfd on kernel >= 5.4 */
    if (events & (VIR_EVENT_HANDLE_READABLE | VIR_EVENT_HANDLE_HANGUP)) {
        /* acrn-dm process has exited */

        if (mon->reboot) {
            VIR_INFO("Domain %s shutdown. Restarting domain.", vm->def->name);
            virAcrnProcessRestart(driver, vm);
        } else {
            /* Technically we need to specify reason based on exit value and
             * status (i.e., normal exit, non-zero exit, or if the acrn-dm has
             * crashed). But by design only parent process can collect child
             * status, so we specify reason as "shutdown" directly.
             */
            VIR_INFO("Domain %s shutdown", vm->def->name);
            virAcrnProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
            if (!vm->persistent)
                virDomainObjListRemove(driver->domains, vm);
        }
    }

}

static acrnMonitor *
acrnMonitorOpenImpl(virDomainObj *vm, struct _acrnConn *driver)
{
    acrnMonitor *mon;
    int pidfd;

    if (acrnMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectNew(acrnMonitorClass)))
        return NULL;

    mon->driver = driver;
    mon->reboot = false;

    virObjectRef(vm);
    mon->vm = vm;

    pidfd = syscall(SYS_pidfd_open, vm->pid, 0);
    if (pidfd == -1) {
        virReportSystemError(errno, "%s", "unable to open pidfd");
        goto cleanup;
    }

    mon->fd = pidfd;

    if (!acrnMonitorRegister(mon)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to register monitor events"));
        goto cleanup;
    }

    return mon;

 cleanup:
    acrnMonitorClose(mon);
    return NULL;
}

acrnMonitor *
acrnMonitorOpen(virDomainObj *vm, struct _acrnConn *driver)
{
    acrnMonitor *mon;

    virObjectRef(vm);
    mon = acrnMonitorOpenImpl(vm, driver);
    virObjectUnref(vm);

    return mon;
}

void
acrnMonitorClose(acrnMonitor *mon)
{
    if (mon == NULL)
        return;

    VIR_DEBUG("cleaning up acrnMonitor %p", mon);

    acrnMonitorUnregister(mon);
    if (mon->fd)
        VIR_FORCE_CLOSE(mon->fd);
    virObjectUnref(mon);
}
