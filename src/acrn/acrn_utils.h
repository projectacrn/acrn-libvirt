/*
 * acrn_utils.h: acrn utils
 * Adapted from bhyve_utils.h. Original license and copyright:
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

#pragma once

#include "driver.h"
#include "domain_event.h"
#include "configmake.h"
#include "virdomainobjlist.h"
#include "virthread.h"
#include "virhostdev.h"
#include "hypervisor/virclosecallbacks.h"
#include "virportallocator.h"

#define ACRN_AUTOSTART_DIR    SYSCONFDIR "/libvirt/acrn/autostart"
#define ACRN_CONFIG_DIR       SYSCONFDIR "/libvirt/acrn"
#define ACRN_STATE_DIR        RUNSTATEDIR "/libvirt/acrn"
#define ACRN_LOG_DIR          LOCALSTATEDIR "/log/libvirt/acrn"

#define ACRN_MAX_SUPPORTED_CPU 256

typedef struct _virAcrnDriverConfig virAcrnDriverConfig;
struct _virAcrnDriverConfig {
    virObject parent;

    char *firmwareDir;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virAcrnDriverConfig, virObjectUnref);

struct _acrnConn {
    virMutex lock;

    struct _virAcrnDriverConfig *config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    virDomainObjList *domains;
    virCaps *caps;
    virDomainXMLOption *xmlopt;
    char *pidfile;
    virSysinfoDef *hostsysinfo;

    virObjectEventState *domainEventState;

    virPortAllocatorRange *remotePorts;

    virHostdevManager *hostdevMgr;

    unsigned acrncaps;
    unsigned grubcaps;

    int host_apicids[ACRN_MAX_SUPPORTED_CPU];
};

typedef struct _acrnConn acrnConn;

struct acrnAutostartData {
    struct _acrnConn *driver;
    virConnectPtr conn;
};
