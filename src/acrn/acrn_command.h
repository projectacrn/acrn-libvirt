/*
 * acrn_command.h: acrn command generation
 * Adapted from bhyve_command.h. Original license and copyright:
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

#include "acrn_domain.h"
#include "acrn_utils.h"

#include "domain_conf.h"
#include "vircommand.h"

#define ACRN_CONFIG_FORMAT_ARGV "acrn-argv"

virCommand *virAcrnProcessBuildAcrnCmd(struct _acrnConn *driver,
                                         virDomainDef *def,
                                         bool dryRun);

virCommand *
virAcrnProcessBuildDestroyCmd(struct _acrnConn *driver,
                               virDomainDef *def);

virCommand *
virAcrnProcessBuildLoadCmd(struct _acrnConn *driver, virDomainDef *def,
                            const char *devmap_file, char **devicesmap_out);
