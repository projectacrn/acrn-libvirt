#include <config.h>

#include "acrn_domain.h"
#include "acrn_device.h"
#include "virstring.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_domain");

static int
acrnDomainDefPostParse(virDomainDefPtr def,
                       unsigned int parseFlags G_GNUC_UNUSED,
                       void *opaque G_GNUC_UNUSED,
                       void *parseOpaque G_GNUC_UNUSED)
{
    /* Add an implicit PCI root controller */
    if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
        return -1;

    return 0;
}

static int
acrnDomainDeviceDefPostParse(virDomainDeviceDefPtr dev,
                             const virDomainDef *def G_GNUC_UNUSED,
                             unsigned int parseFlags G_GNUC_UNUSED,
                             void *opaque G_GNUC_UNUSED,
                             void *parseOpaque G_GNUC_UNUSED)
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

        if (net->model != VIR_DOMAIN_NET_MODEL_VIRTIO) {
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
                             unsigned int parseFlags G_GNUC_UNUSED,
                             void *opaque G_GNUC_UNUSED,
                             void *parseOpaque G_GNUC_UNUSED)
{
    return acrnDomainAssignAddresses(def);
}

static virDomainDefParserConfig virAcrnDriverDomainDefParserConfig = {
    .devicesPostParseCallback = acrnDomainDeviceDefPostParse,
    .domainPostParseCallback = acrnDomainDefPostParse,
    .assignAddressesCallback = acrnDomainDefAssignAddresses,
};

static void *
acrnDomainObjPrivateAlloc(void *opaque G_GNUC_UNUSED)
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
    virBitmapFree(priv->cpuAffinitySet);
    VIR_FREE(priv);
}

static virDomainXMLPrivateDataCallbacks virAcrnDriverPrivateDataCallbacks = {
    .alloc = acrnDomainObjPrivateAlloc,
    .free = acrnDomainObjPrivateFree,
};

static void
acrnDomainDefNamespaceFree(void *nsdata)
{
    acrnDomainXmlNsDefPtr nsdef = nsdata;

    if (!nsdef)
        return;

    if (nsdef->cpu_affinity)
	VIR_FREE(nsdef->cpu_affinity);
    virStringListFreeCount(nsdef->args, nsdef->nargs);
    VIR_FREE(nsdef);
}

static int
acrnDomainDefNamespaceParseConfig(acrnDomainXmlNsDefPtr nsdef,
                                  xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *nodes = NULL;
    xmlNodePtr node;
    int nnodes;

    if ((nnodes = virXPathNodeSet("./acrn:config",
                                  ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid acrn:config node"));
        return -1;
    }

    if (nnodes == 0)
        return 0;

    if (nnodes > 2) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("More than 2 acrn:config nodes"));
        return -1;
    }

    for (node = nodes[0]->children; node; node = node->next) {
        if (node->type == XML_ELEMENT_NODE) {
            if (virXMLNodeNameEqual(node, "rtvm"))
                nsdef->rtvm = true;
            if (virXMLNodeNameEqual(node, "cpu_affinity")) {
                nsdef->cpu_affinity = virXMLPropString(node, "value");
                if (nsdef->cpu_affinity == NULL) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("No CPU specified in acrn:cpu_affinity"));
                    return -1;
                }
	    }
        }
    }

    return 0;
}

static int
acrnDomainDefNamespaceParseCommandlineArgs(acrnDomainXmlNsDefPtr nsdef,
                                           xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *nodes = NULL;
    int nnodes, i;

    if ((nnodes = virXPathNodeSet("./acrn:commandline/acrn:arg",
                                  ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid acrn:arg node"));
        return -1;
    }

    if (nnodes == 0)
        return 0;

    if (VIR_ALLOC_N(nsdef->args, nnodes) < 0) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        return -1;
    }

    for (i = 0; i < nnodes; i++) {
        if (!(nsdef->args[nsdef->nargs++] =
                    virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("No command-line argument specified"));
            return -1;
        }
    }

    return 0;
}

static int
acrnDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
                            void **data)
{
    acrnDomainXmlNsDefPtr nsdata;
    int ret = -1;

    if (VIR_ALLOC(nsdata) < 0)
        return -1;

    if (acrnDomainDefNamespaceParseConfig(nsdata, ctxt) < 0 ||
        acrnDomainDefNamespaceParseCommandlineArgs(nsdata, ctxt) < 0)
        goto cleanup;

    if (nsdata->rtvm || nsdata->nargs || nsdata->cpu_affinity)
        *data = g_steal_pointer(&nsdata);

    ret = 0;

cleanup:
    acrnDomainDefNamespaceFree(nsdata);
    return ret;
}

static void
acrnDomainDefNamespaceFormatXMLConfig(virBufferPtr buf,
                                      acrnDomainXmlNsDefPtr xmlns)
{
    if (!xmlns->rtvm && !xmlns->cpu_affinity)
        return;

    virBufferAddLit(buf, "<acrn:config>\n");
    virBufferAdjustIndent(buf, 2);

    if (xmlns->rtvm)
	    virBufferAddLit(buf, "<acrn:rtvm/>\n");

    if (xmlns->cpu_affinity)
        virBufferEscapeString(buf, "<acrn:cpu_affinity value='%s'/>\n",
                              xmlns->cpu_affinity);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</acrn:config>\n");
}

static void
acrnDomainDefNamespaceFormatXMLCommandlineArgs(virBufferPtr buf,
                                               acrnDomainXmlNsDefPtr cmd)
{
    size_t i;

    if (!cmd->nargs)
        return;

    virBufferAddLit(buf, "<acrn:commandline>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cmd->nargs; i++)
        virBufferEscapeString(buf, "<acrn:arg value='%s'/>\n",
                              cmd->args[i]);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</acrn:commandline>\n");
}

static int
acrnDomainDefNamespaceFormatXML(virBufferPtr buf,
                                void *nsdata)
{
    acrnDomainXmlNsDefPtr xmlns = nsdata;

    acrnDomainDefNamespaceFormatXMLConfig(buf, xmlns);
    acrnDomainDefNamespaceFormatXMLCommandlineArgs(buf, xmlns);

    return 0;
}

static virXMLNamespace virAcrnDriverDomainXMLNamespace = {
    .parse = acrnDomainDefNamespaceParse,
    .free = acrnDomainDefNamespaceFree,
    .format = acrnDomainDefNamespaceFormatXML,
    .prefix = "acrn",
    .uri = "http://libvirt.org/schemas/domain/acrn/1.0",
};

virDomainXMLOptionPtr
virAcrnDriverCreateXMLConf(void)
{
    return virDomainXMLOptionNew(&virAcrnDriverDomainDefParserConfig,
                                 &virAcrnDriverPrivateDataCallbacks,
                                 &virAcrnDriverDomainXMLNamespace,
                                 NULL, NULL);
}
