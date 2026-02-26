/*
 * acrn_domain.h: acrn domain private state headers
 * Adapted from bhyve_domain.h. Original license and copyright:
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
 */

#pragma once

#include "domain_addr.h"
#include "domain_conf.h"

#include "acrn_monitor.h"
#include "virchrdev.h"

typedef struct _acrnDomainObjPrivate acrnDomainObjPrivate;
struct _acrnDomainObjPrivate {
    struct _acrnConn *driver;

    virDomainPCIAddressSet *pciaddrs;
    bool persistentAddrs;

    virChrdevs *devs;

    int *ttyfds;
    acrnMonitor *mon;
};

virDomainXMLOption *virAcrnDriverCreateXMLConf(struct _acrnConn *);

extern virDomainXMLPrivateDataCallbacks virAcrnDriverPrivateDataCallbacks;
extern virDomainDefParserConfig virAcrnDriverDomainDefParserConfig;
extern virXMLNamespace virAcrnDriverDomainXMLNamespace;
