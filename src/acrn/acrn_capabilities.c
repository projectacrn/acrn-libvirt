/*
 * acrn_capabilities.c: acrn capabilities module
 * Adapted from bhyve_capabilities.c. Original license and copyright:
 *
 * Copyright (C) 2014 Roman Bogorodskiy
 * Copyright (C) 2014 Semihalf
 * Copyright (C) 2020 Fabian Freyer
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
#include <sys/utsname.h>
#include <dirent.h>
#include <sys/types.h>

#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "domain_conf.h"
#include "vircommand.h"
#include "acrn_capabilities.h"
#include "acrn_conf.h"

#define VIR_FROM_THIS   VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_capabilities");

static int
acrnGetApicIDs(int *output, int nmax)
{
#define CPU_INFO_PROCFS "/proc/cpuinfo"
    FILE *f;
    char line[512];
    int processor = 0, apicid = -1;
    f = fopen(CPU_INFO_PROCFS, "r");
    if (!f) {
        virReportError(VIR_ERR_OPEN_FAILED, "Failed to open %s",
                       CPU_INFO_PROCFS);
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        if (!STRPREFIX(line, "apicid"))
            continue;
        if (sscanf(line, "apicid : %u", &apicid) <= 0)
            continue;
        output[processor++] = apicid;
        if (processor >= nmax)
            break;
    }

    fclose(f);
    return 0;
}

/* This function gets called when connected */
int
virAcrnNodePrepare(acrnConn *conn)
{
    int ret;

    ret = acrnGetApicIDs(conn->host_apicids, ACRN_MAX_SUPPORTED_CPU);
    if (ret < 0)
        goto out;

    /* Add more preparation actions here. */

out:
    return ret;
}

virCaps *
virAcrnCapsBuild(void)
{
    virCaps *caps;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        return NULL;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM,
                                    VIR_ARCH_X86_64, "acrn",
                                    NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_ACRN,
                                  NULL, NULL, 0, NULL);

    if (!(caps->host.cpu = virCPUProbeHost(caps->host.arch)))
        VIR_WARN("Failed to get host CPU");

    return caps;
}

int
virAcrnDomainCapsFill(virDomainCaps *caps,
                       unsigned int acrncaps G_GNUC_UNUSED,
                       virDomainCapsStringValues *firmwares)
{
    caps->disk.supported = VIR_TRISTATE_BOOL_YES;
    caps->disk.diskDevice.report = true;
    caps->disk.bus.report = true;
    caps->disk.model.report = true;
    VIR_DOMAIN_CAPS_ENUM_SET(caps->disk.diskDevice,
                             VIR_DOMAIN_DISK_DEVICE_DISK,
                             VIR_DOMAIN_DISK_DEVICE_CDROM);

    VIR_DOMAIN_CAPS_ENUM_SET(caps->disk.bus,
                             VIR_DOMAIN_DISK_BUS_SATA,
                             VIR_DOMAIN_DISK_BUS_VIRTIO);

    caps->os.supported = VIR_TRISTATE_BOOL_YES;

    caps->os.loader.supported = VIR_TRISTATE_BOOL_NO;
    caps->os.loader.type.report = true;
    caps->os.loader.readonly.report = true;
    caps->os.loader.supported = VIR_TRISTATE_BOOL_YES;
    VIR_DOMAIN_CAPS_ENUM_SET(caps->os.loader.type,
            VIR_DOMAIN_LOADER_TYPE_PFLASH);
    VIR_DOMAIN_CAPS_ENUM_SET(caps->os.loader.readonly,
            VIR_TRISTATE_BOOL_YES);

    caps->os.loader.values.values = firmwares->values;
    caps->os.loader.values.nvalues = firmwares->nvalues;


    caps->graphics.supported = VIR_TRISTATE_BOOL_NO;
    caps->video.supported = VIR_TRISTATE_BOOL_NO;
    caps->graphics.supported = VIR_TRISTATE_BOOL_YES;
    caps->graphics.type.report = true;
    caps->video.supported = VIR_TRISTATE_BOOL_YES;
    caps->video.modelType.report = true;
    VIR_DOMAIN_CAPS_ENUM_SET(caps->graphics.type, VIR_DOMAIN_GRAPHICS_TYPE_VNC);
    VIR_DOMAIN_CAPS_ENUM_SET(caps->video.modelType, VIR_DOMAIN_VIDEO_TYPE_GOP);

    caps->hostdev.supported = VIR_TRISTATE_BOOL_NO;
    caps->features[VIR_DOMAIN_CAPS_FEATURE_IOTHREADS] = VIR_TRISTATE_BOOL_NO;
    caps->features[VIR_DOMAIN_CAPS_FEATURE_VMCOREINFO] = VIR_TRISTATE_BOOL_NO;
    caps->features[VIR_DOMAIN_CAPS_FEATURE_GENID] = VIR_TRISTATE_BOOL_NO;
    caps->gic.supported = VIR_TRISTATE_BOOL_NO;

    return 0;
}

virDomainCaps *
virAcrnDomainCapsBuild(struct _acrnConn *conn,
                        const char *emulatorbin,
                        const char *machine,
                        virArch arch,
                        virDomainVirtType virttype)
{
    virDomainCaps *caps = NULL;
    unsigned int acrn_caps = 0;
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    size_t firmwares_alloc = 0;
    struct _virAcrnDriverConfig *cfg = virAcrnDriverGetConfig(conn);
    const char *firmware_dir = cfg->firmwareDir;
    virDomainCapsStringValues *firmwares = NULL;

    if (!(caps = virDomainCapsNew(emulatorbin, machine, arch, virttype)))
        goto cleanup;

    if (virAcrnProbeCaps(&acrn_caps)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed probing capabilities"));
        goto cleanup;
    }

    firmwares = g_new0(virDomainCapsStringValues, 1);

    if (virDirOpenIfExists(&dir, firmware_dir) > 0) {
        while ((virDirRead(dir, &entry, firmware_dir)) > 0) {
            VIR_RESIZE_N(firmwares->values, firmwares_alloc, firmwares->nvalues, 1);
            firmwares->values[firmwares->nvalues] = g_strdup_printf("%s/%s",
                                                    firmware_dir, entry->d_name);
            firmwares->nvalues++;
        }
    } else {
        VIR_WARN("Cannot open firmware directory %s", firmware_dir);
    }

    if (virAcrnDomainCapsFill(caps, acrn_caps, firmwares) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(firmwares);
    virObjectUnref(cfg);
    return caps;
}

int
virAcrnProbeCaps(unsigned int *caps)
{
    /* FIXME: Probe acrn-dm binary capability through 'acrn-dm -h' or
     * simple command such as acrn-dm -s,0,xhci and check error report
     * to determine if acrn actually supports below capabilities. For now
     * hard code them.
     */
    *caps = ACRN_CAP_XHCI | \
            ACRN_CAP_CPUTOPOLOGY | \
            ACRN_CAP_SOUND_HDA | \
            ACRN_CAP_VNC_PASSWORD;
    return 0;
}
