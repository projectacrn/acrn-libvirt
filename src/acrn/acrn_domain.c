#include <config.h>

#include "acrn_domain.h"
#include "acrn_device.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_domain");

static int
acrnDomainDefPostParse(virDomainDefPtr def,
                       virCapsPtr caps ATTRIBUTE_UNUSED,
                       unsigned int parseFlags ATTRIBUTE_UNUSED,
                       void *opaque ATTRIBUTE_UNUSED,
                       void *parseOpaque ATTRIBUTE_UNUSED)
{
    /* Add an implicit PCI root controller */
    if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
        return -1;

    return 0;
}

static int
acrnDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                             const virDomainDef *def ATTRIBUTE_UNUSED,
                             virCapsPtr caps ATTRIBUTE_UNUSED,
                             unsigned int parseFlags ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED,
                             void *parseOpaque ATTRIBUTE_UNUSED)
{
    virDomainDeviceInfoPtr info;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK: {
        virDomainDiskDefPtr disk = dev->data.disk;
        info = virDomainDeviceGetInfo(dev);

        if (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE &&
            virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_BLOCK) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("disk source %s not supported"),
                           virStorageTypeToString(disk->src->type));
            return -1;
        }

        if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
            if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("disk device %s not supported"),
                               virDomainDiskDeviceTypeToString(disk->device));
                return -1;
            }

            if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("disk address type %s not supported"),
                               virDomainDeviceAddressTypeToString(info->type));
                return -1;
            }
        } else if (disk->bus == VIR_DOMAIN_DISK_BUS_SATA) {
            /* SATA disks must use VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE */
            if (disk->device != VIR_DOMAIN_DISK_DEVICE_DISK &&
                disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("disk device %s not supported"),
                               virDomainDiskDeviceTypeToString(disk->device));
                return -1;
            }
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("disk bus %s not supported"),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_NET: {
        virDomainNetDefPtr net = dev->data.net;
        info = virDomainDeviceGetInfo(dev);

        if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET) {
            if (!net->ifname) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("net dev undefined"));
                return -1;
            }
        } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
            if (!virDomainNetGetActualBridgeName(net)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("bridge name undefined"));
                return -1;
            }
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("net type %s not supported"),
                           virDomainNetTypeToString(net->type));
            return -1;
        }

        if (STRNEQ_NULLABLE(net->model, "virtio")) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("only virtio-net is supported"));
            return -1;
        }

        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("net address type %s not supported"),
                           virDomainDeviceAddressTypeToString(info->type));
            return -1;
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        virDomainHostdevDefPtr hostdev = dev->data.hostdev;
        info = virDomainDeviceGetInfo(dev);

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("hostdev mode %s not supported"),
                           virDomainHostdevModeTypeToString(hostdev->mode));
            return -1;
        }

        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("hostdev type %s not supported"),
                           virDomainHostdevSubsysTypeToString(
                               hostdev->source.subsys.type));
            return -1;
        }

        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            virPCIDeviceAddressIsEmpty(&hostdev->source.subsys.u.pci.addr)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("PCI hostdev has no valid address"));
            return -1;
        }

        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("hostdev address type %s not supported"),
                           virDomainDeviceAddressTypeToString(info->type));
            return -1;
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_CONTROLLER: {
        virDomainControllerDefPtr ctrl = dev->data.controller;

        if (ctrl->type != VIR_DOMAIN_CONTROLLER_TYPE_SATA &&
            ctrl->type != VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL &&
            ctrl->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("controller type %s not supported"),
                           virDomainControllerTypeToString(ctrl->type));
            return -1;
        }

        if (ctrl->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            if ((virDomainControllerModelPCI)ctrl->model !=
                VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("PCI controller model %s not supported"),
                               virDomainControllerModelPCITypeToString(ctrl->model));
                return -1;
            }
        } else {
            info = virDomainDeviceGetInfo(dev);

            if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("controller address type %s not supported"),
                               virDomainDeviceAddressTypeToString(info->type));
                return -1;
            }
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_CHR: {
        virDomainChrDefPtr chr = dev->data.chr;

        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
            if (chr->source->type == VIR_DOMAIN_CHR_TYPE_TCP) {
                if (!chr->source->data.tcp.listen) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("serial over tcp must be in listen mode"));
                    return -1;
                }
            } else if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY &&
                       chr->source->type != VIR_DOMAIN_CHR_TYPE_DEV &&
                       chr->source->type != VIR_DOMAIN_CHR_TYPE_STDIO) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("serial type %s not supported"),
                               virDomainChrTypeToString(chr->source->type));
                return -1;
            }

            if (chr->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE &&
                chr->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("serial target type %s not supported"),
                               virDomainChrConsoleTargetTypeToString(
                                   chr->targetType));
                return -1;
            }

            if (chr->target.port > 1) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("serial port %d not supported"),
                               chr->target.port);
                return -1;
            }
        } else if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE) {
            info = virDomainDeviceGetInfo(dev);

            if (chr->source->type != VIR_DOMAIN_CHR_TYPE_PTY &&
                chr->source->type != VIR_DOMAIN_CHR_TYPE_DEV &&
                chr->source->type != VIR_DOMAIN_CHR_TYPE_FILE &&
                chr->source->type != VIR_DOMAIN_CHR_TYPE_STDIO &&
                chr->source->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("console type %s not supported"),
                               virDomainChrTypeToString(chr->source->type));
                return -1;
            }

            /*
             * VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE will later be
             * converted to VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL.
             *
             * These types are considered as an implicit device and
             * will be ignored.
             *
             * Only def->consoles[0] is allowed to be a serial port.
             */
            if (chr->targetType != VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE &&
                chr->targetType != VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL &&
                chr->targetType != VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("console target type %s not supported"),
                               virDomainChrConsoleTargetTypeToString(
                                   chr->targetType));
                return -1;
            }

            if (chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO &&
                info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
                info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("virtio-console address type %s not supported"),
                               virDomainDeviceAddressTypeToString(
                                   info->type));
                return -1;
            }
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("chr device type %s not supported"),
                           virDomainChrDeviceTypeToString(chr->deviceType));
            return -1;
        }
        break;
    }
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_RNG:
    default:
        virReportError(VIR_ERR_XML_ERROR,
                       _("device type %s not supported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    return 0;
}

static int
acrnDomainDefAssignAddresses(virDomainDef *def,
                             virCapsPtr caps ATTRIBUTE_UNUSED,
                             unsigned int parseFlags ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED,
                             void *parseOpaque ATTRIBUTE_UNUSED)
{
    return acrnDomainAssignAddresses(def);
}

static virDomainDefParserConfig virAcrnDriverDomainDefParserConfig = {
    .devicesPostParseCallback = acrnDomainDeviceDefPostParse,
    .domainPostParseCallback = acrnDomainDefPostParse,
    .assignAddressesCallback = acrnDomainDefAssignAddresses,
};

static void *
acrnDomainObjPrivateAlloc(void *opaque ATTRIBUTE_UNUSED)
{
    acrnDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

void
acrnDomainTtyCleanup(acrnDomainObjPrivatePtr priv)
{
    size_t i = priv->nttys;

    while (i--) {
        VIR_FREE(priv->ttys[i].slave);
        VIR_FORCE_CLOSE(priv->ttys[i].fd);
        priv->ttys[i].fd = 0;
    }

    priv->nttys = 0;
}

static void
acrnDomainObjPrivateFree(void *data)
{
    /* priv is guaranteed non-NULL */
    acrnDomainObjPrivatePtr priv = data;

    acrnDomainTtyCleanup(priv);
    VIR_FREE(priv);
}

static virDomainXMLPrivateDataCallbacks virAcrnDriverPrivateDataCallbacks = {
    .alloc = acrnDomainObjPrivateAlloc,
    .free = acrnDomainObjPrivateFree,
};

virDomainXMLOptionPtr
virAcrnDriverCreateXMLConf(void)
{
    return virDomainXMLOptionNew(&virAcrnDriverDomainDefParserConfig,
                                 &virAcrnDriverPrivateDataCallbacks,
                                 NULL, NULL, NULL);
}
