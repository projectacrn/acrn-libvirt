/*
 * acrn_command.c: acrn command generation
 * Adapted from bhyve_command.c. Original license and copyright:
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

#include <config.h>

#include "acrn_capabilities.h"
#include "acrn_command.h"
#include "acrn_domain.h"
#include "acrn_conf.h"
#include "acrn_driver.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virlog.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"

#define VIR_FROM_THIS VIR_FROM_ACRN

#define ACRN_MONITOR_DIR            "/var/lib/libvirt/acrn"
#define ACRN_MANAGER_DIR            "/var/lib/life_mngr"

VIR_LOG_INIT("acrn.acrn_command");

static int
acrnBuildNetArgStr(const virDomainDef *def,
                    virDomainNetDef *net,
                    struct _acrnConn *driver G_GNUC_UNUSED,
                    virCommand *cmd,
                    bool dryRun)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    char *realifname = NULL;
    char *brname = NULL;
    char *nic_model = NULL;
    int ret = -1;
    int tapfd = -1;
    virDomainNetType actualType = virDomainNetGetActualType(net);

    if (net->model == VIR_DOMAIN_NET_MODEL_VIRTIO) {
        nic_model = g_strdup("virtio-net");
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("NIC model is not supported"));
        return -1;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        brname = g_strdup(virDomainNetGetActualBridgeName(net));
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Network type %1$d is not supported"),
                       virDomainNetGetActualType(net));
        goto cleanup;
    }

    if (!dryRun) {
        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, NULL, &tapfd, 1,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
                                           virDomainNetGetActualPortOptionsIsolated(net),
                                           NULL, net->mtu, NULL,
                                           VIR_NETDEV_TAP_CREATE_IFUP | VIR_NETDEV_TAP_CREATE_PERSIST) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "failed to create tap device");
            goto cleanup;
        }

        realifname = g_strdup(net->ifname);
    } else {
        realifname = g_strdup("tap0");
    }


    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,%s,tap=%s,mac=%s",
                           net->info.addr.pci.slot, nic_model,
                           realifname, virMacAddrFormat(&net->mac, macaddr));

    ret = 0;
 cleanup:
    if (tapfd >= 0)
        VIR_FORCE_CLOSE(tapfd);
    if (ret < 0)
        VIR_FREE(net->ifname);
    VIR_FREE(brname);
    VIR_FREE(realifname);
    VIR_FREE(nic_model);

    return ret;
}

static int
acrnBuildConsoleArgStr(const virDomainDef *def, virCommand *cmd)
{
    virDomainChrDef *chr = NULL;
    ssize_t i;

    /* According to libvirt documentation:
     * Due to historical reasons, the serial and console elements have
     * partially overlapping scopes.
     */

    /* Serial devices */
    for (i = 0; i < def->nserials; i++) {
        chr = def->serials[i];
        if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY &&
            chr->source->type != VIR_DOMAIN_CHR_TYPE_DEV &&
            chr->source->type != VIR_DOMAIN_CHR_TYPE_STDIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    "only pty, dev and stdio serial types are supported");
            return -1;
        }

        if (chr->target.port > 2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                    _("only two serial ports are supported"));
            return -1;
        }

        virCommandAddArg(cmd, "-l");
        if (chr->source->type == VIR_DOMAIN_CHR_TYPE_STDIO) {
            virCommandAddArgFormat(cmd, "com%d,stdio", chr->target.port + 1);
        } else {
            virCommandAddArgFormat(cmd, "com%d,%s",
                    chr->target.port + 1, chr->source->data.file.path);
        }
    }

    return 0;
}

static int
acrnBuildAHCIControllerArgStr(const virDomainDef *def,
                               virDomainControllerDef *controller,
                               struct _acrnConn *driver G_GNUC_UNUSED,
                               virCommand *cmd)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *disk_source;
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        g_auto(virBuffer) device = VIR_BUFFER_INITIALIZER;
        virDomainDiskDef *disk = def->disks[i];

        if (disk->bus != VIR_DOMAIN_DISK_BUS_SATA)
            continue;

        if (disk->info.addr.drive.controller != controller->idx)
            continue;

        VIR_DEBUG("disk %zu controller %d", i, controller->idx);

        if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
            (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk type"));
            return -1;
        }

        if (virDomainDiskTranslateSourcePool(disk) < 0)
            return -1;

        disk_source = virDomainDiskGetSource(disk);

        if ((disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
            (disk_source == NULL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cdrom device without source path not supported"));
            return -1;
        }

        switch (disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_DISK:
            virBufferAsprintf(&device, ",hd:%s", disk_source);
            break;
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            virBufferAsprintf(&device, ",cd:%s", disk_source);
            break;
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        case VIR_DOMAIN_DISK_DEVICE_LUN:
        case VIR_DOMAIN_DISK_DEVICE_LAST:
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported disk device"));
            return -1;
        }
        virBufferAddBuffer(&buf, &device);
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,ahci%s",
                           controller->info.addr.pci.slot,
                           virBufferCurrentContent(&buf));

    return 0;
}

static int
acrnBuildUSBControllerArgStr(const virDomainDef *def,
                              virDomainControllerDef *controller,
                              virCommand *cmd)
{
    size_t i;
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    int found = 0;

    virBufferAsprintf(&opt, "%d:%d,xhci",
                      controller->info.addr.pci.slot,
                      controller->info.addr.pci.function);

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];

        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        virBufferAsprintf(&opt, ",%x-%x",
                          hostdev->source.subsys.u.usb.bus,
                          hostdev->source.subsys.u.usb.device);
        found = 1;
    }

    if (found) {
        virCommandAddArg(cmd, "-s");
        virCommandAddArgBuffer(cmd, &opt);
    }

    return 0;
}

static int
acrnBuildVirtIODiskArgStr(const virDomainDef *def G_GNUC_UNUSED,
                           virDomainDiskDef *disk,
                           virCommand *cmd)
{
    const char *disk_source;

    if (virDomainDiskTranslateSourcePool(disk) < 0)
        return -1;

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return -1;
    }

    if ((virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE) &&
        (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk type"));
        return -1;
    }

    disk_source = virDomainDiskGetSource(disk);

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:0,virtio-blk,%s",
                           disk->info.addr.pci.slot,
                           disk_source);

    return 0;
}

static int
acrnBuildDiskArgStr(const virDomainDef *def,
                     virDomainDiskDef *disk,
                     virCommand *cmd)
{
    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        /* Handled by acrnBuildAHCIControllerArgStr() */
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (acrnBuildVirtIODiskArgStr(def, disk, cmd) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported disk device"));
        return -1;
    }
    return 0;
}

static int
acrnBuildControllerArgStr(const virDomainDef *def,
                           virDomainControllerDef *controller,
                           struct _acrnConn *driver,
                           virCommand *cmd,
                           unsigned *nusbcontrollers,
                           unsigned *nisacontrollers)
{
    switch (controller->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        if (controller->model != VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported PCI controller model: only PCI root supported"));
            return -1;
        }
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        if (acrnBuildAHCIControllerArgStr(def, controller, driver, cmd) < 0)
            return -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (++*nusbcontrollers > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only single USB controller is supported"));
            return -1;
        }

        if (acrnBuildUSBControllerArgStr(def, controller, cmd) < 0)
            return -1;
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
        if (++*nisacontrollers > 1) {
             virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            "%s", _("only single ISA controller is supported"));
             return -1;
        }
        virCommandAddArg(cmd, "-s");
        virCommandAddArgFormat(cmd, "%d:0,lpc",
                                controller->info.addr.pci.slot);
        break;
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unsupported controller device"));
        return -1;

    }
    return 0;
}

static int
acrnBuildGraphicsVNCArgStr(const virDomainDef *def,
                           virDomainGraphicsDef *graphics,
                           virDomainVideoDef *video,
                           struct _acrnConn *driver,
                           virCommand *cmd,
                           bool dryRun)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    virDomainGraphicsListenDef *glisten = NULL;
    bool escapeAddr;
    unsigned short port;

    if (!(glisten = virDomainGraphicsGetListen(graphics, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing listen element"));
        return -1;
    }

    switch (glisten->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        virBufferAddLit(&opt, ",tcp=");

        if (!graphics->data.vnc.autoport &&
            (graphics->data.vnc.port < 5900 ||
             graphics->data.vnc.port > 65535)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vnc port must be in range [5900,65535]"));
            return -1;
        }

        if (glisten->address) {
            escapeAddr = strchr(glisten->address, ':') != NULL;
            if (escapeAddr)
                virBufferAsprintf(&opt, "[%s]", glisten->address);
            else
                virBufferAdd(&opt, glisten->address, -1);
        }

        if (!dryRun) {
            if (graphics->data.vnc.autoport) {
                if (virPortAllocatorAcquire(driver->remotePorts, &port) < 0)
                    return -1;
                graphics->data.vnc.port = port;
            } else {
                if (virPortAllocatorSetUsed(graphics->data.vnc.port) < 0)
                    VIR_WARN("Failed to mark VNC port '%d' as used by '%s'",
                             graphics->data.vnc.port, def->name);
            }
        }

        virBufferAsprintf(&opt, ":%d", graphics->data.vnc.port);
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported listen type"));
        return -1;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainGraphicsListenType, glisten->type);
        return -1;
    }

    if (graphics->data.vnc.auth.passwd) {
        if (!(acrnDriverGetAcrnCaps(driver) & ACRN_CAP_VNC_PASSWORD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VNC Password authentication not supported by acrn"));
            return -1;
        }

        if (strchr(graphics->data.vnc.auth.passwd, ',')) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Password may not contain ',' character"));
            return -1;
        }

        virBufferAsprintf(&opt, ",password=%s", graphics->data.vnc.auth.passwd);
    } else {
        if (!(acrnDriverGetAcrnCaps(driver) & ACRN_CAP_VNC_PASSWORD))
            VIR_WARN("%s", _("Security warning: VNC auth is not supported."));
        else
            VIR_WARN("%s", _("Security warning: VNC is used without authentication."));
    }

    if (video->res)
        virBufferAsprintf(&opt, ",w=%d,h=%d", video->res->x, video->res->y);

    if (video->driver)
        virBufferAsprintf(&opt, ",vga=%s",
                          virDomainVideoVGAConfTypeToString(video->driver->vgaconf));

    virCommandAddArg(cmd, "-s");
    virCommandAddArgBuffer(cmd, &opt);
    return 0;
}

static int
acrnBuildGraphicsSDLArgStr(const virDomainDef *def G_GNUC_UNUSED,
                           virDomainGraphicsDef *graphics,
                           virDomainVideoDef *video,
                           struct _acrnConn *driver G_GNUC_UNUSED,
                           virCommand *cmd,
                           bool dryRun G_GNUC_UNUSED)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    char *display = graphics->data.sdl.display;

    virBufferAsprintf(&opt, "%x:%x,virtio-gpu,geometry=",
                      video->info.addr.pci.slot,
                      video->info.addr.pci.function);

    if (graphics->data.sdl.fullscreen) {
        virBufferAsprintf(&opt, "fullscreen%s", display ? display : ":0");
    } else {
        /* Resolution was specified in video element */
        virBufferAsprintf(&opt, "%dx%d+0+0",
                          video->res->x ? video->res->x : 1920,
                          video->res->y ? video->res->y : 1080);
    }

    virCommandAddArg(cmd, "-s");
    virCommandAddArgBuffer(cmd, &opt);
    return 0;
}

static int
acrnBuildGraphicsArgStr(const virDomainDef *def,
                         virDomainGraphicsDef *graphics,
                         virDomainVideoDef *video,
                         struct _acrnConn *driver,
                         virCommand *cmd,
                         bool dryRun)
{
    switch(graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        return acrnBuildGraphicsVNCArgStr(def, graphics, video, driver, cmd, dryRun);
    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        return acrnBuildGraphicsSDLArgStr(def, graphics, video, driver, cmd, dryRun);
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s", "Only VNC and SDL are supported");
        break;
    }

    return -1;
}

static int
acrnBuildSoundArgStr(const virDomainDef *def G_GNUC_UNUSED,
                      virDomainSoundDef *sound,
                      virDomainAudioDef *audio,
                      struct _acrnConn *driver,
                      virCommand *cmd)
{
    g_auto(virBuffer) params = VIR_BUFFER_INITIALIZER;

    if (!(acrnDriverGetAcrnCaps(driver) & ACRN_CAP_SOUND_HDA)) {
        /* Currently, acrn only supports "hda" sound devices, so
           if it's not supported, sound devices are not supported at all */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Sound devices emulation is not supported by given acrn binary"));
        return -1;
    }

    if (sound->model != VIR_DOMAIN_SOUND_MODEL_ICH7) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Sound device model is not supported"));
        return -1;
    }

    virCommandAddArg(cmd, "-s");

    if (audio) {
        switch (audio->type) {
        case  VIR_DOMAIN_AUDIO_TYPE_OSS:
            if (virDomainAudioIOCommonIsSet(&audio->input) ||
                virDomainAudioIOCommonIsSet(&audio->output)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("cannot set common audio backend settings"));
                return -1;
            }

            if (audio->backend.oss.input.dev)
                virBufferAsprintf(&params, ",play=%s",
                                  audio->backend.oss.input.dev);

            if (audio->backend.oss.output.dev)
                virBufferAsprintf(&params, ",rec=%s",
                                  audio->backend.oss.output.dev);

            break;

        case VIR_DOMAIN_AUDIO_TYPE_NONE:
        case VIR_DOMAIN_AUDIO_TYPE_ALSA:
        case VIR_DOMAIN_AUDIO_TYPE_COREAUDIO:
        case VIR_DOMAIN_AUDIO_TYPE_JACK:
        case VIR_DOMAIN_AUDIO_TYPE_PULSEAUDIO:
        case VIR_DOMAIN_AUDIO_TYPE_SDL:
        case VIR_DOMAIN_AUDIO_TYPE_SPICE:
        case VIR_DOMAIN_AUDIO_TYPE_FILE:
        case VIR_DOMAIN_AUDIO_TYPE_DBUS:
        case VIR_DOMAIN_AUDIO_TYPE_PIPEWIRE:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported audio backend '%1$s'"),
                           virDomainAudioTypeTypeToString(audio->type));
            return -1;
        case VIR_DOMAIN_AUDIO_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainAudioType, audio->type);
            return -1;
        }
    }

    virCommandAddArgFormat(cmd, "%d:%d,hda%s",
                           sound->info.addr.pci.slot,
                           sound->info.addr.pci.function,
                           virBufferCurrentContent(&params));

    return 0;
}

static int
acrnBuildFSArgStr(const virDomainDef *def G_GNUC_UNUSED,
                   virDomainFSDef *fs,
                   virCommand *cmd)
{
    g_auto(virBuffer) params = VIR_BUFFER_INITIALIZER;

    switch (fs->type) {
    case VIR_DOMAIN_FS_TYPE_MOUNT:
        break;
    case VIR_DOMAIN_FS_TYPE_BLOCK:
    case VIR_DOMAIN_FS_TYPE_FILE:
    case VIR_DOMAIN_FS_TYPE_TEMPLATE:
    case VIR_DOMAIN_FS_TYPE_RAM:
    case VIR_DOMAIN_FS_TYPE_BIND:
    case VIR_DOMAIN_FS_TYPE_VOLUME:
    case VIR_DOMAIN_FS_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported filesystem type '%1$s'"),
                       virDomainFSTypeToString(fs->type));
        return -1;
    }

    switch (fs->fsdriver) {
    case VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT:
        /* The only supported driver by acrn currently */
        break;
    case VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS:
    case VIR_DOMAIN_FS_DRIVER_TYPE_PATH:
    case VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE:
    case VIR_DOMAIN_FS_DRIVER_TYPE_LOOP:
    case VIR_DOMAIN_FS_DRIVER_TYPE_NBD:
    case VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP:
    case VIR_DOMAIN_FS_DRIVER_TYPE_MTP:
    case VIR_DOMAIN_FS_DRIVER_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported filesystem driver '%1$s'"),
                       virDomainFSDriverTypeToString(fs->fsdriver));
        return -1;
    }

    switch (fs->accessmode) {
    case VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH:
        /* This is the only supported mode for now, does not need specific configuration */
        break;
    case VIR_DOMAIN_FS_ACCESSMODE_MAPPED:
    case VIR_DOMAIN_FS_ACCESSMODE_SQUASH:
    case VIR_DOMAIN_FS_ACCESSMODE_DEFAULT:
    case VIR_DOMAIN_FS_ACCESSMODE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported filesystem accessmode '%1$s'"),
                       virDomainFSAccessModeTypeToString(fs->accessmode));
        return -1;
    }

    if (fs->readonly)
        virBufferAddLit(&params, ",ro");

    virCommandAddArg(cmd, "-s");
    virCommandAddArgFormat(cmd, "%d:%d,virtio-9p,%s=%s%s",
                           fs->info.addr.pci.slot,
                           fs->info.addr.pci.function,
                           fs->dst,
                           fs->src->path,
                           virBufferCurrentContent(&params));

    return 0;
}

static int
acrnBuildPassthroughDevicesArgStr(const virDomainDef *def G_GNUC_UNUSED,
                                  virDomainHostdevDef *hostdev,
                                  virCommand *cmd)
{
    int ret = -1;
    virDomainHostdevSubsys *subsys = &hostdev->source.subsys;
    virDomainHostdevSubsysPCI *pcisrc;

    switch (subsys->type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        pcisrc = &subsys->u.pci;
        virCommandAddArg(cmd, "-s");
        virCommandAddArgFormat(cmd, "%d:%d,passthru,%x/%x/%x",
                               hostdev->info->addr.pci.slot,
                               hostdev->info->addr.pci.function,
                               pcisrc->addr.bus,
                               pcisrc->addr.slot,
                               pcisrc->addr.function);
        ret = 0;
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        /* Do nothing, handled when we process USB controller */
        ret = 0;
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported host device type '%s'"),
                       virDomainHostdevSubsysTypeToString(subsys->type));
        break;
    }

    return ret;
}

static int
acrnBuildCpuArgStr(struct _acrnConn *driver,
                   const virDomainDef *def, virCommand *cmd)
{
    g_auto(virBuffer) opt = VIR_BUFFER_INITIALIZER;
    virBitmap *cpumask;
    size_t pos = 0;
    unsigned count = 0;
    unsigned nvcpus = virDomainDefGetVcpus(def);

    if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC) {
        cpumask = def->cpumask;
        if (!cpumask) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "CPU affinity not specified with static vcpu placement");
            return -1;
        }

        while ((pos = virBitmapNextSetBit(cpumask, pos)) != -1) {
            virBufferAsprintf(&opt, count ? ",%d" : "%d",
                              driver->host_apicids[pos]);
            count++;
            if (count == nvcpus)
                break;
        }

        if (count) {
            virCommandAddArg(cmd, "--cpu_affinity");
            virCommandAddArgBuffer(cmd, &opt);
        }
    } else if (def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) {
        /* TODO: Auto placement */
    }

    return 0;
}

virCommand *
virAcrnProcessBuildAcrnCmd(struct _acrnConn *driver, virDomainDef *def,
                             bool dryRun)
{
    /*
     * /usr/sbin/acrn -c 2 -m 256 -AI -H -P \
     *            -s 0:0,hostbridge \
     *            -s 1:0,virtio-net,tap0 \
     *            -s 2:0,ahci-hd,${IMG} \
     *            -S 31,uart,stdio \
     *            vm0
     */
    g_autoptr(virCommand) cmd = virCommandNew(ACRN);
    size_t i;
    unsigned nusbcontrollers = 0;
    unsigned nisacontrollers = 0;

    /* CPUs */
    if (acrnBuildCpuArgStr(driver, def, cmd) < 0)
        return NULL;

    /* Memory */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%lluM",
                           VIR_DIV_UP(virDomainDefGetMemoryInitial(def), 1024));

    /* OVMF */
    if (def->os.bootloader == NULL && def->os.loader) {
        virCommandAddArg(cmd, "--ovmf");
        virCommandAddArgFormat(cmd, "%s", def->os.loader->path);
    }

    virCommandAddArgList(cmd, "-s", "0:0,hostbridge", NULL);

    /* Devices */
    for (i = 0; i < def->ncontrollers; i++) {
        if (acrnBuildControllerArgStr(def, def->controllers[i], driver, cmd,
                                       &nusbcontrollers, &nisacontrollers) < 0)
            return NULL;
    }
    for (i = 0; i < def->nnets; i++) {
        if (acrnBuildNetArgStr(def, def->nets[i], driver, cmd, dryRun) < 0)
            return NULL;
    }
    for (i = 0; i < def->ndisks; i++) {
        if (acrnBuildDiskArgStr(def, def->disks[i], cmd) < 0)
            return NULL;
    }

    if (def->ngraphics && def->nvideos) {
        if (def->ngraphics == 1 && def->nvideos == 1) {
            if (acrnBuildGraphicsArgStr(def, def->graphics[0], def->videos[0],
                                         driver, cmd, dryRun) < 0)
                return NULL;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Multiple graphics devices are not supported"));
             return NULL;
        }
    }

    for (i = 0; i < def->nhostdevs; i++) {
        if (acrnBuildPassthroughDevicesArgStr(def, def->hostdevs[i], cmd) < 0)
            return NULL;
    }

    for (i = 0; i < def->nsounds; i++) {
        if (acrnBuildSoundArgStr(def, def->sounds[i],
                                  virDomainDefFindAudioByID(def, def->sounds[i]->audioId),
                                  driver, cmd) < 0)
            return NULL;
    }

    for (i = 0; i < def->nfss; i++) {
        if (acrnBuildFSArgStr(def, def->fss[i], cmd) < 0)
            return NULL;
    }

    if (acrnBuildConsoleArgStr(def, cmd) < 0)
        return NULL;

    if (def->namespaceData) {
        acrnDomainCmdlineDef *acrncmd;

        VIR_WARN("Booting the guest using command line pass-through feature, "
                 "which could potentially cause inconsistent state and "
                 "upgrade issues");

        acrncmd = def->namespaceData;
        for (i = 0; i < acrncmd->num_args; i++)
            virCommandAddArg(cmd, acrncmd->args[i]);
    }

    virCommandAddArgList(cmd, "--logger_setting", "kmsg,level=3;disk,level=3", NULL);

    virCommandAddArg(cmd, def->name);

    return g_steal_pointer(&cmd);
}

virCommand *
virAcrnProcessBuildDestroyCmd(struct _acrnConn *driver G_GNUC_UNUSED,
                               virDomainDef *def)
{
    virCommand *cmd = virCommandNew(ACRNCTL);

    virCommandAddArgList(cmd, "stop", "-f", def->name, NULL);

    return cmd;
}
