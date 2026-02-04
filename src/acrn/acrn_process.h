/*
 * acrn_process.h: acrn process management
 * Adapted from bhyve_process.h. Original license and copyright:
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

#include "acrn_utils.h"

int
acrnProcessPrepareDomain(acrnConn *driver,
                          virDomainObj *vm,
                          unsigned int flags);

int virAcrnProcessStart(virConnect *conn,
                         virDomainObj *vm,
                         virDomainRunningReason reason,
                         unsigned int flags);

int virAcrnProcessStop(struct _acrnConn *driver,
                        virDomainObj *vm,
                        virDomainShutoffReason reason);

int virAcrnProcessRestart(struct _acrnConn *driver,
                           virDomainObj *vm);

int virAcrnProcessShutdown(virDomainObj *vm);

int virAcrnGetDomainTotalCpuStats(virDomainObj *vm,
                                   unsigned long long *cpustats);

void virAcrnProcessReconnectAll(struct _acrnConn *driver);

typedef enum {
    VIR_ACRN_PROCESS_START_AUTODESTROY = 1 << 0,
} acrnProcessStartFlags;
