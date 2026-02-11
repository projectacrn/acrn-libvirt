/*
 * acrn_capabilities.h: acrn capabilities module
 * Adapted from bhyve_capabilities.h. Original license and copyright:
 *
 * Copyright (C) 2014 Semihalf
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

#include "capabilities.h"
#include "conf/domain_capabilities.h"

#include "acrn_utils.h"

virCaps *virAcrnCapsBuild(void);
int virAcrnDomainCapsFill(virDomainCaps *caps,
                           unsigned int acrncaps,
                           virDomainCapsStringValues *firmwares);
virDomainCaps *virAcrnDomainCapsBuild(acrnConn *conn,
                                       const char *emulatorbin,
                                       const char *machine,
                                       virArch arch,
                                       virDomainVirtType virttype);

typedef enum {
    ACRN_CAP_RTC_UTC = 1 << 0,
    ACRN_CAP_AHCI32SLOT = 1 << 1,
    ACRN_CAP_NET_E1000 = 1 << 2,
    ACRN_CAP_LPC_BOOTROM = 1 << 3,
    ACRN_CAP_FBUF = 1 << 4,
    ACRN_CAP_XHCI = 1 << 5,
    ACRN_CAP_CPUTOPOLOGY = 1 << 6,
    ACRN_CAP_SOUND_HDA = 1 << 7,
    ACRN_CAP_VNC_PASSWORD = 1 << 8,
    ACRN_CAP_VIRTIO_9P = 1 << 9,
} virAcrnCapsFlags;

int virAcrnProbeCaps(unsigned int *caps);
