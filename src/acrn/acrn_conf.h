/*
 * acrn_conf.h: acrn config file
 * Adapted from bhyve_conf.h. Original license and copyright:
 *
 * Copyright (C) 2017 Roman Bogorodskiy
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

struct _virAcrnDriverConfig *virAcrnDriverConfigNew(void);
struct _virAcrnDriverConfig *virAcrnDriverGetConfig(struct _acrnConn *driver);
int virAcrnLoadDriverConfig(struct _virAcrnDriverConfig *cfg,
                             const char *filename);

typedef struct _acrnDomainCmdlineDef acrnDomainCmdlineDef;
struct _acrnDomainCmdlineDef {
    size_t num_args;
    char **args;
};

void acrnDomainCmdlineDefFree(acrnDomainCmdlineDef *def);
