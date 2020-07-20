# libvirt’s read-only privilege issue
From https://access.redhat.com/libvirt-privesc-vulnerabilities:

As the libvirt API has evolved over time, the line between “privileged” and “unprivileged” operations became less clear. API calls that were originally exposed read-only, gained more capabilities that made them more powerful, but introduced security risks that were not obvious at the time.

Administrative changes made to `/etc/libvirt/libvirtd.conf` may affect your level of exposure:
- If you have enabled the setting `listen_tcp`, network users that can reach the libvirt port may be able to conduct an attack.
- If access to libvirt is restricted by changing `unix_sock_ro_perms` to something more restrictive than `0777`, only those users able to `connect()` to the socket will be able to attack libvirtd. For example, the following allows only members of the `libvirt` group:
```
unix_sock_group = "libvirt"
unix_sock_ro_perms = "0770"
```

We recommend that users at least adopt coarse-grained access control and properly configure `unix_sock_group` and `unix_sock_ro_perms` in order to minimize libvirt's attack surface.
