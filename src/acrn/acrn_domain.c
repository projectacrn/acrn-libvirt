/*
 * acrn_domain.c: acrn domain private state
 * Adapted from bhyve_domain.c. Original license and copyright:
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
 */

#include <config.h>

#include "acrn_driver.h"
#include "acrn_conf.h"
#include "acrn_device.h"
#include "acrn_domain.h"
#include "acrn_capabilities.h"
#include "viralloc.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_domain");

static void *
acrnDomainObjPrivateAlloc(void *opaque)
{
    acrnDomainObjPrivate *priv = g_new0(acrnDomainObjPrivate, 1);

    priv->driver = opaque;

    if (!(priv->devs = virChrdevAlloc())) {
        g_free(priv);
        return NULL;
    }

    return priv;
}

static void
acrnDomainObjPrivateFree(void *data)
{
    acrnDomainObjPrivate *priv = data;

    virDomainPCIAddressSetFree(priv->pciaddrs);

    virChrdevFree(priv->devs);
    g_free(priv);
}

virDomainXMLPrivateDataCallbacks virAcrnDriverPrivateDataCallbacks = {
    .alloc = acrnDomainObjPrivateAlloc,
    .free = acrnDomainObjPrivateFree,
};

static bool
acrnDomainDefNeedsISAController(virDomainDef *def)
{
    if (def->os.bootloader == NULL && def->os.loader)
        return true;

    if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_EFI)
        return true;

    if (def->nserials || def->nconsoles)
        return true;

    if (def->ngraphics && def->nvideos)
        return true;

    return false;
}

static int
acrnDomainDefPostParse(virDomainDef *def,
                        unsigned int parseFlags G_GNUC_UNUSED,
                        void *opaque,
                        void *parseOpaque G_GNUC_UNUSED)
{
    struct _acrnConn *driver = opaque;
    g_autoptr(virCaps) caps = acrnDriverGetCapabilities(driver);
    if (!caps)
        return -1;

    if (!virCapabilitiesDomainSupported(caps, def->os.type,
                                        def->os.arch,
                                        def->virtType,
                                        true))
        return -1;

    /* Add an implicit PCI root controller */
    if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
        return -1;

    if (acrnDomainDefNeedsISAController(def))
        if (virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_ISA, 0,
                                           VIR_DOMAIN_CONTROLLER_MODEL_ISA_DEFAULT) < 0)
            return -1;

    return 0;
}

static int
acrnDomainDiskDefAssignAddress(struct _acrnConn *driver G_GNUC_UNUSED,
                                virDomainDiskDef *def,
                                const virDomainDef *vmdef G_GNUC_UNUSED)
{
    int idx = virDiskNameToIndex(def->dst);

    if (idx < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unknown disk name '%1$s' and no address specified"),
                       def->dst);
        return -1;
    }

    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

        def->info.addr.drive.controller = idx;
        def->info.addr.drive.unit = 0;

        def->info.addr.drive.bus = 0;
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        break;
    }
    return 0;
}

static int
acrnDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                              const virDomainDef *def,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque,
                              void *parseOpaque G_GNUC_UNUSED)
{
    struct _acrnConn *driver = opaque;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDef *disk = dev->data.disk;

        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            acrnDomainDiskDefAssignAddress(driver, disk, def) < 0)
            return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        virDomainControllerDef *cont = dev->data.controller;

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
             cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) &&
            cont->idx != 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("pci-root and pcie-root controllers should have index 0"));
            return -1;
        }
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO &&
        dev->data.video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT) {
        dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_GOP;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->source->type == VIR_DOMAIN_CHR_TYPE_NMDM) {
        virDomainChrDef *chr = dev->data.chr;

        if (!chr->source->data.nmdm.master) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];

            virUUIDFormat(def->uuid, uuidstr);

            chr->source->data.nmdm.master = g_strdup_printf("/dev/nmdm%sA", uuidstr);
            chr->source->data.nmdm.slave = g_strdup_printf("/dev/nmdm%sB", uuidstr);
        }
    }

    return 0;
}

static int
acrnDomainDefAssignAddresses(virDomainDef *def,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED,
                              void *parseOpaque G_GNUC_UNUSED)
{
    if (acrnDomainAssignAddresses(def, NULL) < 0)
        return -1;

    return 0;
}

virDomainXMLOption *
virAcrnDriverCreateXMLConf(struct _acrnConn *driver)
{
    virDomainXMLOption *ret = NULL;

    virAcrnDriverDomainDefParserConfig.priv = driver;

    ret = virDomainXMLOptionNew(&virAcrnDriverDomainDefParserConfig,
                                &virAcrnDriverPrivateDataCallbacks,
                                &virAcrnDriverDomainXMLNamespace,
                                NULL, NULL, NULL);

    virDomainXMLOptionSetCloseCallbackAlloc(ret, virCloseCallbacksDomainAlloc);

    return ret;
}


static int
acrnDomainDeviceDefValidate(const virDomainDeviceDef *dev,
                             const virDomainDef *def G_GNUC_UNUSED,
                             void *opaque G_GNUC_UNUSED,
                             void *parseOpaque G_GNUC_UNUSED)
{
    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER &&
        dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_ISA &&
        dev->data.controller->idx != 0) {
        return -1;
    }

    return 0;
}

virDomainDefParserConfig virAcrnDriverDomainDefParserConfig = {
    .devicesPostParseCallback = acrnDomainDeviceDefPostParse,
    .domainPostParseCallback = acrnDomainDefPostParse,
    .assignAddressesCallback = acrnDomainDefAssignAddresses,
    .deviceValidateCallback = acrnDomainDeviceDefValidate,

    .features = VIR_DOMAIN_DEF_FEATURE_FW_AUTOSELECT,
};

static void
acrnDomainDefNamespaceFree(void *nsdata)
{
    acrnDomainCmdlineDef *cmd = nsdata;

    acrnDomainCmdlineDefFree(cmd);
}

static int
acrnDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
                             void **data)
{
    acrnDomainCmdlineDef *cmd = NULL;
    xmlNodePtr *nodes = NULL;
    int n;
    size_t i;
    int ret = -1;

    cmd = g_new0(acrnDomainCmdlineDef, 1);

    n = virXPathNodeSet("./acrn:commandline/acrn:arg", ctxt, &nodes);
    if (n == 0)
        ret = 0;
    if (n <= 0)
        goto cleanup;

    cmd->args = g_new0(char *, n);

    for (i = 0; i < n; i++) {
        cmd->args[cmd->num_args] = virXMLPropString(nodes[i], "value");
        if (cmd->args[cmd->num_args] == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No acrn command-line argument specified"));
            goto cleanup;
        }
        cmd->num_args++;
    }

    *data = g_steal_pointer(&cmd);
    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    acrnDomainDefNamespaceFree(cmd);

    return ret;
}

static int
acrnDomainDefNamespaceFormatXML(virBuffer *buf,
                                 void *nsdata)
{
    acrnDomainCmdlineDef *cmd = nsdata;
    size_t i;

    if (!cmd->num_args)
        return 0;

    virBufferAddLit(buf, "<acrn:commandline>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cmd->num_args; i++)
        virBufferEscapeString(buf, "<acrn:arg value='%s'/>\n",
                              cmd->args[i]);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</acrn:commandline>\n");

    return 0;
}

virXMLNamespace virAcrnDriverDomainXMLNamespace = {
    .parse = acrnDomainDefNamespaceParse,
    .free = acrnDomainDefNamespaceFree,
    .format = acrnDomainDefNamespaceFormatXML,
    .prefix = "acrn",
    .uri = "http://libvirt.org/schemas/domain/acrn/1.0",

};
