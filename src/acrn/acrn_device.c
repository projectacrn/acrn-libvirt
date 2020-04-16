#include <config.h>

#include "acrn_device.h"
#include "domain_addr.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_ACRN

VIR_LOG_INIT("acrn.acrn_device");

static int
acrnCollectPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                      virDomainDeviceDefPtr dev ATTRIBUTE_UNUSED,
                      virDomainDeviceInfoPtr info,
                      void *opaque)
{
    virDomainPCIAddressSetPtr addrs;
    virPCIDeviceAddressPtr addr;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        return 0;

    addrs = opaque;
    addr = &info->addr.pci;

    if (!virPCIDeviceAddressIsEmpty(addr) &&
        virDomainPCIAddressReserveAddr(
                addrs, addr,
                VIR_PCI_CONNECT_TYPE_PCI_DEVICE, 0) < 0) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        virPCIDeviceAddressFormat(&buf, *addr, false);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to reserve PCI addr: %s"),
                       virBufferCurrentContent(&buf));
        virBufferFreeAndReset(&buf);
        return -1;
    }

    return 0;
}

static virDomainPCIAddressSetPtr
acrnDomainPCIAddressSetCreate(virDomainDefPtr def, unsigned int nbuses)
{
    virDomainPCIAddressSetPtr addrs;
    virPCIDeviceAddress lpc_addr;

    if (!(addrs = virDomainPCIAddressSetAlloc(nbuses))) {
        virReportError(VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    if (virDomainPCIAddressBusSetModel(
                &addrs->buses[0],
                VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to set PCI bus model"));
        goto error;
    }

    memset(&lpc_addr, 0, sizeof(lpc_addr));
    lpc_addr.slot = 0x1;

    /* explicitly reserve 0:1:0 for LPC-ISA bridge */
    if (virDomainPCIAddressReserveAddr(
                addrs, &lpc_addr,
                VIR_PCI_CONNECT_TYPE_PCI_DEVICE, 0) < 0) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        virPCIDeviceAddressFormat(&buf, lpc_addr, false);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to reserve PCI addr for LPC-ISA bridge: %s"),
                       virBufferCurrentContent(&buf));
        virBufferFreeAndReset(&buf);
        goto error;
    }

    if (virDomainDeviceInfoIterate(def, acrnCollectPCIAddress, addrs) < 0)
        goto error;

    return addrs;

error:
    virDomainPCIAddressSetFree(addrs);
    return NULL;
}

static int
acrnAssignPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                     virDomainDeviceDefPtr dev,
                     virDomainDeviceInfoPtr info,
                     void *opaque)
{
    virDomainPCIAddressSetPtr addrs = opaque;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (virDeviceInfoPCIAddressWanted(info) &&
            virDomainPCIAddressReserveNextAddr(addrs, info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            goto fail;
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER: {
        virDomainControllerDefPtr ctrl = dev->data.controller;

        /* PCI hostbridge is always 0:0:0 */
        if (ctrl->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            virDeviceInfoPCIAddressWanted(info) &&
            virDomainPCIAddressReserveNextAddr(addrs, info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            goto fail;
        break;
    }
    case VIR_DOMAIN_DEVICE_CHR: {
        virDomainChrDefPtr chr = dev->data.chr;

        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO &&
            virDeviceInfoPCIAddressWanted(info) &&
            virDomainPCIAddressReserveNextAddr(addrs, info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            goto fail;
        break;
    }
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_RNG:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("device type %s"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    return 0;

fail:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("PCI addr assignment failed for device type %s"),
                   virDomainDeviceTypeToString(dev->type));
    return -1;
}

static int
acrnDomainAssignPCIAddresses(virDomainDefPtr def)
{
    virDomainPCIAddressSetPtr addrs;
    int ret = -1;

    if (!(addrs = acrnDomainPCIAddressSetCreate(def, 1)))
        goto cleanup;

    if (virDomainDeviceInfoIterate(def, acrnAssignPCIAddress, addrs) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virDomainPCIAddressSetFree(addrs);
    return ret;
}

int
acrnDomainAssignAddresses(virDomainDefPtr def)
{
    return acrnDomainAssignPCIAddresses(def);
}
