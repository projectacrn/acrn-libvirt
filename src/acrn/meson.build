acrn_sources = files(
  'acrn_capabilities.c',
  'acrn_command.c',
  'acrn_conf.c',
  'acrn_parse_command.c',
  'acrn_device.c',
  'acrn_domain.c',
  'acrn_driver.c',
  'acrn_monitor.c',
  'acrn_process.c',
)

driver_source_files += acrn_sources
stateful_driver_source_files += acrn_sources

if conf.has('WITH_ACRN')
  acrn_driver_impl = static_library(
    'virt_driver_acrn_impl',
    [
      acrn_sources,
    ],
    dependencies: [
      access_dep,
      libkvm_dep,
      libutil_dep,
      src_dep,
    ],
    include_directories: [
      conf_inc_dir,
      hypervisor_inc_dir,
    ],
  )

  virt_modules += {
    'name': 'virt_driver_acrn',
    'link_whole': [
      acrn_driver_impl,
    ],
    'link_args': [
      libvirt_no_undefined,
    ],
  }

  virt_daemons += {
    'name': 'virtacrnd',
    'c_args': [
      '-DDAEMON_NAME="virtacrnd"',
      '-DMODULE_NAME="acrn"'
    ],
  }

  virt_conf_files += files('acrn.conf')
  virt_aug_files += files('libvirtd_acrn.aug')
  virt_test_aug_files += {
    'name': 'test_libvirtd_acrn.aug',
    'aug': files('test_libvirtd_acrn.aug.in'),
    'conf': files('acrn.conf'),
    'test_name': 'libvirtd_acrn',
    'test_srcdir': meson.current_source_dir(),
    'test_builddir': meson.current_build_dir(),
  }

  virt_daemon_confs += {
    'name': 'virtacrnd',
  }
endif
