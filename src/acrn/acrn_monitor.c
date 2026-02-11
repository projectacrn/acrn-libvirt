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
    int kq;
    int watch;
    bool reboot;
};

static virClass *acrnMonitorClass;

static void
acrnMonitorDispose(void *obj)
{
    acrnMonitor *mon = obj;

    VIR_FORCE_CLOSE(mon->kq);
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
    mon->watch = virEventAddHandle(mon->kq,
                                   VIR_EVENT_HANDLE_READABLE |
                                   VIR_EVENT_HANDLE_ERROR |
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
acrnMonitorIO(int watch, int kq, int events G_GNUC_UNUSED, void *opaque)
{
#if 0
    const struct timespec zerowait = { 0, 0 };
    acrnMonitor *mon = opaque;
    virDomainObj *vm = mon->vm;
    struct _acrnConn *driver = mon->driver;
    const char *name;
    struct kevent kev;
    int rc, status;

    if (watch != mon->watch || kq != mon->kq) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("event from unexpected fd %1$d!=%2$d / watch %3$d!=%4$d"),
                       mon->kq, kq, mon->watch, watch);
        return;
    }

    rc = kevent(kq, NULL, 0, &kev, 1, &zerowait);
    if (rc < 0) {
        virReportSystemError(errno, "%s", _("Unable to query kqueue"));
        return;
    }

    if (rc == 0)
        return;

    if ((kev.flags & EV_ERROR) != 0) {
        virReportSystemError(kev.data, "%s", _("Unable to query kqueue"));
        return;
    }

    if (kev.filter == EVFILT_PROC && (kev.fflags & NOTE_EXIT) != 0) {
        if ((pid_t)kev.ident != vm->pid) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("event from unexpected proc %1$ju!=%2$ju"),
                           (uintmax_t)vm->pid, (uintmax_t)kev.ident);
            return;
        }

        name = vm->def->name;
        status = kev.data;
        if (WIFSIGNALED(status) && WCOREDUMP(status)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Guest %1$s got signal %2$d and crashed"),
                           name, WTERMSIG(status));
            virAcrnProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED);
        } else if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0 || mon->reboot) {
                /* 0 - reboot */
                VIR_INFO("Guest %s rebooted; restarting domain.", name);
                virAcrnProcessRestart(driver, vm);
            } else if (WEXITSTATUS(status) < 3) {
                /* 1 - shutdown, 2 - halt, 3 - triple fault. others - error */
                VIR_INFO("Guest %s shut itself down; destroying domain.", name);
                virAcrnProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
            } else {
                VIR_INFO("Guest %s had an error and exited with status %d; destroying domain.",
                         name, WEXITSTATUS(status));
                virAcrnProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_UNKNOWN);
            }
        }
    }
#endif
    (void)watch;
    (void)kq;
    (void)opaque;
}

static acrnMonitor *
acrnMonitorOpenImpl(virDomainObj *vm, struct _acrnConn *driver)
{
    acrnMonitor *mon;

    if (acrnMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectNew(acrnMonitorClass)))
        return NULL;

    mon->driver = driver;
    mon->reboot = false;

    virObjectRef(vm);
    mon->vm = vm;

#if 0
    struct kevent kev;

    mon->kq = kqueue();
    if (mon->kq < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to create kqueue"));
        goto cleanup;
    }

    EV_SET(&kev, vm->pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, mon);
    if (kevent(mon->kq, &kev, 1, NULL, 0, NULL) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to register process kevent"));
        goto cleanup;
    }
#endif

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
    virObjectUnref(mon);
}
