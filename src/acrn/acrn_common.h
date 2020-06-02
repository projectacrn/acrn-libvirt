/*
 * Commmon IOCTL ID defination for VHM/DM
 */
#define _IC_ID(x, y) (((x)<<24)|(y))
#define IC_ID 0x43UL

/* General */
#define IC_ID_GEN_BASE                  0x0UL
#define IC_GET_PLATFORM_INFO            _IC_ID(IC_ID, IC_ID_GEN_BASE + 0x03)

/* ACRN guest severity */
enum acrn_vm_severity {
    SEVERITY_SAFETY_VM = 0x40U,
    SEVERITY_RTVM = 0x30U,
    SEVERITY_SOS = 0x20U,
    SEVERITY_STANDARD_VM = 0x10U,
};

enum acrn_vm_load_order {
    PRE_LAUNCHED_VM = 0,
    SOS_VM,
    POST_LAUNCHED_VM,
    MAX_LOAD_ORDER
};

#define MAX_VM_OS_NAME_LEN      32U

typedef struct acrn_vm_config acrnVmCfg;
typedef acrnVmCfg *acrnVmCfgPtr;
struct acrn_vm_config {
    enum acrn_vm_load_order load_order; /* specify the load order of VM */
    char name[MAX_VM_OS_NAME_LEN];      /* VM name identifier, useful for debug. */
    const uint8_t uuid[16];             /* UUID of the VM */
    uint8_t reserved[2];                /* Temporarily reserve it so that don't need to update
                                         * the users of get_platform_info frequently.
                                         */
    uint8_t severity;                   /* severity of the VM */
    uint64_t cpu_affinity;              /* The set bits represent the pCPUs the vCPUs of
                                         * the VM may run on.
                                         */
    uint64_t guest_flags;               /* VM flags that we want to configure for guest */
    /*
     * The following are hv-specific members and are thus opaque.
     * vm_config_entry_size determines the real size of this structure.
     */
} __attribute__((aligned(8)));

typedef struct platform_info acrnPlatformInfo;
typedef acrnPlatformInfo *acrnPlatformInfoPtr;
struct platform_info {
    /** Hardware Information */
    /** Physical CPU number */
    uint16_t cpu_num;

    /** version of this structure */
    uint16_t version;

    /** Align the size of version & hardware info to 128Bytes. */
    uint8_t reserved0[124];

    /** Configuration Information */
    /** Maximum vCPU number for one VM. */
    uint16_t max_vcpus_per_vm;

    /** Maximum Kata container number in SOS VM */
    uint8_t max_kata_containers;

    uint8_t reserved1[7];

    /** Number of configured VMs */
    uint16_t max_vms;

    /**
     * The size of acrn_vm_config is various on different platforms.
     * This is the size of this struct which is used for the caller
     * to parse the vm_configs array.
     */
    uint32_t vm_config_entry_size;

    /**
     * Address to an array of struct acrn_vm_config, containing all
     * the configurations of all VMs. VHM treats it as an opague data
     * structure.
     *                                    *
     * The size of one array element is vm_config_entry_size while
     * the number of elements is max_vms.
     */
    uint64_t vm_configs_addr;

    /** Align the size of Configuration info to 128Bytes. */
    uint8_t reserved2[104];
} __attribute__((aligned(8)));
