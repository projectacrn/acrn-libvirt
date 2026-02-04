/*
 * acrn_monitor.h: Tear-down or reboot acrn domains on guest shutdown
 * Adapted from bhyve_monitor.h. Original license and copyright:
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

#pragma once

#include "internal.h"
#include "domain_conf.h"
#include "acrn_utils.h"

typedef struct _acrnMonitor acrnMonitor;

acrnMonitor *acrnMonitorOpen(virDomainObj *vm, struct _acrnConn *driver);
void acrnMonitorClose(acrnMonitor *mon);

void acrnMonitorSetReboot(acrnMonitor *mon);
