/*
 * Commmon IOCTL ID defination for VHM/DM
 */
#define _IC_ID(x, y) (((x)<<24)|(y))
#define IC_ID 0x43UL

#define ACRN_IOCTL_TYPE			0xA2

#define IC_GET_PLATFORM_INFO		_IOR(ACRN_IOCTL_TYPE, 0x03, struct acrn_platform_info)
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

typedef struct acrn_platform_info acrnPlatformInfo;
typedef acrnPlatformInfo *acrnPlatformInfoPtr;
#define ACRN_PLATFORM_LAPIC_IDS_MAX	64
struct acrn_platform_info {
	struct {
		/** Physical CPU number of the platform */
		__u16	cpu_num;
		/** Version of this structure */
		__u16	version;
		/** Order of the number of threads sharing L2 cache */
		__u32	l2_cat_shift;
		/** Order of the number of threads sharing L3 cache */
		__u32	l3_cat_shift;
		/** IDs of LAPICs of all threads */
		__u8	lapic_ids[ACRN_PLATFORM_LAPIC_IDS_MAX];
		/** Reserved for alignment and should be 0 */
		__u8	reserved[52];
	} hw;

	struct {
		/** Maximum number of vCPU of a VM */
		__u16	max_vcpus_per_vm;
		/** Maximum number of VM */
		__u16	max_vms;
		/** Size of configuration of a VM */
		__u32	vm_config_size;

		/** Memory address which user space provided to
		 *  store the VM configurations
		 */
		void	*vm_configs_addr;
		/** Maximum number of VM for Kata containers */
		__u64	max_kata_containers;
		__u8	reserved[104];
	} sw;
};
