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
                       unsigned int acrncaps,
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
    if (acrncaps & ACRN_CAP_LPC_BOOTROM) {
        caps->os.loader.type.report = true;
        caps->os.loader.readonly.report = true;
        caps->os.loader.supported = VIR_TRISTATE_BOOL_YES;
        VIR_DOMAIN_CAPS_ENUM_SET(caps->os.loader.type,
                                 VIR_DOMAIN_LOADER_TYPE_PFLASH);
        VIR_DOMAIN_CAPS_ENUM_SET(caps->os.loader.readonly,
                                 VIR_TRISTATE_BOOL_YES);

        caps->os.loader.values.values = firmwares->values;
        caps->os.loader.values.nvalues = firmwares->nvalues;
    }


    caps->graphics.supported = VIR_TRISTATE_BOOL_NO;
    caps->video.supported = VIR_TRISTATE_BOOL_NO;
    if (acrncaps & ACRN_CAP_FBUF) {
        caps->graphics.supported = VIR_TRISTATE_BOOL_YES;
        caps->graphics.type.report = true;
        caps->video.supported = VIR_TRISTATE_BOOL_YES;
        caps->video.modelType.report = true;
        VIR_DOMAIN_CAPS_ENUM_SET(caps->graphics.type, VIR_DOMAIN_GRAPHICS_TYPE_VNC);
        VIR_DOMAIN_CAPS_ENUM_SET(caps->video.modelType, VIR_DOMAIN_VIDEO_TYPE_GOP);
    }

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

static int
acrnProbeCapsDeviceHelper(unsigned int *caps,
                           char *binary,
                           const char *bus,
                           const char *device,
                           const char *errormsg,
                           unsigned int flag)
{
    g_autofree char *error = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int exit;

    cmd = virCommandNew(binary);
    virCommandAddArgList(cmd, bus, device, NULL);
    virCommandSetErrorBuffer(cmd, &error);
    if (virCommandRun(cmd, &exit) < 0)
        return -1;

    if (strstr(error, errormsg) == NULL)
        *caps |= flag;

    return 0;
}

static int
acrnProbeCapsFromHelp(unsigned int *caps, char *binary)
{
    g_autofree char *help = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int exit;

    cmd = virCommandNew(binary);
    virCommandAddArg(cmd, "-h");
    virCommandSetErrorBuffer(cmd, &help);
    if (virCommandRun(cmd, &exit) < 0)
        return -1;

    if (strstr(help, "-u:") != NULL)
        *caps |= ACRN_CAP_RTC_UTC;

    /* "-c vcpus" was there before CPU topology support was introduced,
     * then it became
     * "-c [[cpus=]numcpus][,sockets=n][,cores=n][,threads=n] */
    if (strstr(help, "-c vcpus") == NULL)
        *caps |= ACRN_CAP_CPUTOPOLOGY;

    return 0;
}

static int
acrnProbeCapsAHCI32Slot(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,ahci",
                                      "pci slot 0:0: unknown device \"ahci\"",
                                      ACRN_CAP_AHCI32SLOT);
}


static int
acrnProbeCapsNetE1000(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,e1000",
                                      "pci slot 0:0: unknown device \"e1000\"",
                                      ACRN_CAP_NET_E1000);
}

static int
acrnProbeCapsLPC_Bootrom(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-l",
                                      "bootrom",
                                      "acrn: invalid lpc device configuration 'bootrom'",
                                      ACRN_CAP_LPC_BOOTROM);
}


static int
acrnProbeCapsFramebuffer(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,fbuf",
                                      "pci slot 0:0: unknown device \"fbuf\"",
                                      ACRN_CAP_FBUF);
}


static int
acrnProbeCapsXHCIController(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,xhci",
                                      "pci slot 0:0: unknown device \"xhci\"",
                                      ACRN_CAP_FBUF);
}


static int
acrnProbeCapsSoundHda(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,hda",
                                      "pci slot 0:0: unknown device \"hda\"",
                                      ACRN_CAP_SOUND_HDA);
}


static int
acrnProbeCapsVNCPassword(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,fbuf,password=",
                                      "Invalid fbuf emulation \"password\"",
                                      ACRN_CAP_VNC_PASSWORD);
}


static int
acrnProbeCapsVirtio9p(unsigned int *caps, char *binary)
{
    return acrnProbeCapsDeviceHelper(caps, binary,
                                      "-s",
                                      "0,virtio-9p",
                                      "pci slot 0:0: unknown device \"hda\"",
                                      ACRN_CAP_VIRTIO_9P);
}


int
virAcrnProbeCaps(unsigned int *caps)
{
    char *binary;
    int ret = 0;

    binary = virFindFileInPath("acrn");
    if (binary == NULL)
        goto out;

    if ((ret = acrnProbeCapsFromHelp(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsAHCI32Slot(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsNetE1000(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsLPC_Bootrom(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsFramebuffer(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsXHCIController(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsSoundHda(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsVNCPassword(caps, binary)))
        goto out;

    if ((ret = acrnProbeCapsVirtio9p(caps, binary)))
        goto out;

 out:
    VIR_FREE(binary);
    return ret;
}
