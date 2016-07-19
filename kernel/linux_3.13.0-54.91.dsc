-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Format: 1.0
Source: linux
Binary: linux-source-3.13.0, linux-doc, linux-headers-3.13.0-54, linux-libc-dev, linux-tools-common, linux-tools-3.13.0-54, linux-cloud-tools-common, linux-cloud-tools-3.13.0-54, linux-image-3.13.0-54-generic, linux-image-extra-3.13.0-54-generic, linux-headers-3.13.0-54-generic, linux-image-3.13.0-54-generic-dbgsym, linux-tools-3.13.0-54-generic, linux-cloud-tools-3.13.0-54-generic, linux-udebs-generic, linux-image-3.13.0-54-generic-lpae, linux-image-extra-3.13.0-54-generic-lpae, linux-headers-3.13.0-54-generic-lpae, linux-image-3.13.0-54-generic-lpae-dbgsym, linux-tools-3.13.0-54-generic-lpae, linux-cloud-tools-3.13.0-54-generic-lpae, linux-udebs-generic-lpae, linux-image-3.13.0-54-lowlatency, linux-image-extra-3.13.0-54-lowlatency, linux-headers-3.13.0-54-lowlatency, linux-image-3.13.0-54-lowlatency-dbgsym, linux-tools-3.13.0-54-lowlatency, linux-cloud-tools-3.13.0-54-lowlatency, linux-udebs-lowlatency, linux-image-3.13.0-54-powerpc-e500,
 linux-image-extra-3.13.0-54-powerpc-e500, linux-headers-3.13.0-54-powerpc-e500, linux-image-3.13.0-54-powerpc-e500-dbgsym, linux-tools-3.13.0-54-powerpc-e500, linux-cloud-tools-3.13.0-54-powerpc-e500, linux-udebs-powerpc-e500, linux-image-3.13.0-54-powerpc-e500mc, linux-image-extra-3.13.0-54-powerpc-e500mc, linux-headers-3.13.0-54-powerpc-e500mc, linux-image-3.13.0-54-powerpc-e500mc-dbgsym, linux-tools-3.13.0-54-powerpc-e500mc, linux-cloud-tools-3.13.0-54-powerpc-e500mc, linux-udebs-powerpc-e500mc, linux-image-3.13.0-54-powerpc-smp, linux-image-extra-3.13.0-54-powerpc-smp, linux-headers-3.13.0-54-powerpc-smp, linux-image-3.13.0-54-powerpc-smp-dbgsym, linux-tools-3.13.0-54-powerpc-smp, linux-cloud-tools-3.13.0-54-powerpc-smp, linux-udebs-powerpc-smp, linux-image-3.13.0-54-powerpc64-emb, linux-image-extra-3.13.0-54-powerpc64-emb, linux-headers-3.13.0-54-powerpc64-emb, linux-image-3.13.0-54-powerpc64-emb-dbgsym, linux-tools-3.13.0-54-powerpc64-emb,
 linux-cloud-tools-3.13.0-54-powerpc64-emb, linux-udebs-powerpc64-emb, linux-image-3.13.0-54-powerpc64-smp, linux-image-extra-3.13.0-54-powerpc64-smp, linux-headers-3.13.0-54-powerpc64-smp, linux-image-3.13.0-54-powerpc64-smp-dbgsym, linux-tools-3.13.0-54-powerpc64-smp, linux-cloud-tools-3.13.0-54-powerpc64-smp, linux-udebs-powerpc64-smp, kernel-image-3.13.0-54-generic-di, nic-modules-3.13.0-54-generic-di, nic-shared-modules-3.13.0-54-generic-di, serial-modules-3.13.0-54-generic-di, ppp-modules-3.13.0-54-generic-di, pata-modules-3.13.0-54-generic-di, firewire-core-modules-3.13.0-54-generic-di, scsi-modules-3.13.0-54-generic-di, plip-modules-3.13.0-54-generic-di, floppy-modules-3.13.0-54-generic-di, fat-modules-3.13.0-54-generic-di, nfs-modules-3.13.0-54-generic-di, md-modules-3.13.0-54-generic-di, multipath-modules-3.13.0-54-generic-di, usb-modules-3.13.0-54-generic-di, pcmcia-storage-modules-3.13.0-54-generic-di, fb-modules-3.13.0-54-generic-di,
 input-modules-3.13.0-54-generic-di, mouse-modules-3.13.0-54-generic-di, irda-modules-3.13.0-54-generic-di, parport-modules-3.13.0-54-generic-di, nic-pcmcia-modules-3.13.0-54-generic-di, pcmcia-modules-3.13.0-54-generic-di, nic-usb-modules-3.13.0-54-generic-di, sata-modules-3.13.0-54-generic-di, crypto-modules-3.13.0-54-generic-di, squashfs-modules-3.13.0-54-generic-di, speakup-modules-3.13.0-54-generic-di, virtio-modules-3.13.0-54-generic-di, fs-core-modules-3.13.0-54-generic-di, fs-secondary-modules-3.13.0-54-generic-di, storage-core-modules-3.13.0-54-generic-di, block-modules-3.13.0-54-generic-di, message-modules-3.13.0-54-generic-di, vlan-modules-3.13.0-54-generic-di,
 ipmi-modules-3.13.0-54-generic-di
Architecture: all i386 amd64 armhf arm64 x32 powerpc ppc64el
Version: 3.13.0-54.91
Maintainer: Ubuntu Kernel Team <kernel-team@lists.ubuntu.com>
Standards-Version: 3.9.4.0
Vcs-Git: http://kernel.ubuntu.com/git-repos/ubuntu/ubuntu-trusty.git
Build-Depends: debhelper (>= 5), cpio, module-init-tools, kernel-wedge (>= 2.24ubuntu1), makedumpfile [amd64 i386], libelf-dev, libnewt-dev, libiberty-dev, rsync, libdw-dev, libpci-dev, dpkg (>= 1.16.0~ubuntu4), pkg-config, flex, bison, libunwind8-dev, openssl, libaudit-dev, bc, python-dev, gawk, device-tree-compiler [powerpc], u-boot-tools [powerpc], libc6-dev-ppc64 [powerpc]
Build-Depends-Indep: xmlto, docbook-utils, ghostscript, transfig, bzip2, sharutils, asciidoc
Package-List: 
 block-modules-3.13.0-54-generic-di udeb debian-installer standard
 crypto-modules-3.13.0-54-generic-di udeb debian-installer extra
 fat-modules-3.13.0-54-generic-di udeb debian-installer standard
 fb-modules-3.13.0-54-generic-di udeb debian-installer standard
 firewire-core-modules-3.13.0-54-generic-di udeb debian-installer standard
 floppy-modules-3.13.0-54-generic-di udeb debian-installer standard
 fs-core-modules-3.13.0-54-generic-di udeb debian-installer standard
 fs-secondary-modules-3.13.0-54-generic-di udeb debian-installer standard
 input-modules-3.13.0-54-generic-di udeb debian-installer standard
 ipmi-modules-3.13.0-54-generic-di udeb debian-installer standard
 irda-modules-3.13.0-54-generic-di udeb debian-installer standard
 kernel-image-3.13.0-54-generic-di udeb debian-installer extra
 linux-cloud-tools-3.13.0-54 deb devel optional
 linux-cloud-tools-3.13.0-54-generic deb devel optional
 linux-cloud-tools-3.13.0-54-generic-lpae deb devel optional
 linux-cloud-tools-3.13.0-54-lowlatency deb devel optional
 linux-cloud-tools-3.13.0-54-powerpc-e500 deb devel optional
 linux-cloud-tools-3.13.0-54-powerpc-e500mc deb devel optional
 linux-cloud-tools-3.13.0-54-powerpc-smp deb devel optional
 linux-cloud-tools-3.13.0-54-powerpc64-emb deb devel optional
 linux-cloud-tools-3.13.0-54-powerpc64-smp deb devel optional
 linux-cloud-tools-common deb kernel optional
 linux-doc deb doc optional
 linux-headers-3.13.0-54 deb devel optional
 linux-headers-3.13.0-54-generic deb devel optional
 linux-headers-3.13.0-54-generic-lpae deb devel optional
 linux-headers-3.13.0-54-lowlatency deb devel optional
 linux-headers-3.13.0-54-powerpc-e500 deb devel optional
 linux-headers-3.13.0-54-powerpc-e500mc deb devel optional
 linux-headers-3.13.0-54-powerpc-smp deb devel optional
 linux-headers-3.13.0-54-powerpc64-emb deb devel optional
 linux-headers-3.13.0-54-powerpc64-smp deb devel optional
 linux-image-3.13.0-54-generic deb kernel optional
 linux-image-3.13.0-54-generic-dbgsym deb devel optional
 linux-image-3.13.0-54-generic-lpae deb kernel optional
 linux-image-3.13.0-54-generic-lpae-dbgsym deb devel optional
 linux-image-3.13.0-54-lowlatency deb kernel optional
 linux-image-3.13.0-54-lowlatency-dbgsym deb devel optional
 linux-image-3.13.0-54-powerpc-e500 deb kernel optional
 linux-image-3.13.0-54-powerpc-e500-dbgsym deb devel optional
 linux-image-3.13.0-54-powerpc-e500mc deb kernel optional
 linux-image-3.13.0-54-powerpc-e500mc-dbgsym deb devel optional
 linux-image-3.13.0-54-powerpc-smp deb kernel optional
 linux-image-3.13.0-54-powerpc-smp-dbgsym deb devel optional
 linux-image-3.13.0-54-powerpc64-emb deb kernel optional
 linux-image-3.13.0-54-powerpc64-emb-dbgsym deb devel optional
 linux-image-3.13.0-54-powerpc64-smp deb kernel optional
 linux-image-3.13.0-54-powerpc64-smp-dbgsym deb devel optional
 linux-image-extra-3.13.0-54-generic deb kernel optional
 linux-image-extra-3.13.0-54-generic-lpae deb kernel optional
 linux-image-extra-3.13.0-54-lowlatency deb kernel optional
 linux-image-extra-3.13.0-54-powerpc-e500 deb kernel optional
 linux-image-extra-3.13.0-54-powerpc-e500mc deb kernel optional
 linux-image-extra-3.13.0-54-powerpc-smp deb kernel optional
 linux-image-extra-3.13.0-54-powerpc64-emb deb kernel optional
 linux-image-extra-3.13.0-54-powerpc64-smp deb kernel optional
 linux-libc-dev deb devel optional
 linux-source-3.13.0 deb devel optional
 linux-tools-3.13.0-54 deb devel optional
 linux-tools-3.13.0-54-generic deb devel optional
 linux-tools-3.13.0-54-generic-lpae deb devel optional
 linux-tools-3.13.0-54-lowlatency deb devel optional
 linux-tools-3.13.0-54-powerpc-e500 deb devel optional
 linux-tools-3.13.0-54-powerpc-e500mc deb devel optional
 linux-tools-3.13.0-54-powerpc-smp deb devel optional
 linux-tools-3.13.0-54-powerpc64-emb deb devel optional
 linux-tools-3.13.0-54-powerpc64-smp deb devel optional
 linux-tools-common deb kernel optional
 linux-udebs-generic udeb debian-installer optional
 linux-udebs-generic-lpae udeb debian-installer optional
 linux-udebs-lowlatency udeb debian-installer optional
 linux-udebs-powerpc-e500 udeb debian-installer optional
 linux-udebs-powerpc-e500mc udeb debian-installer optional
 linux-udebs-powerpc-smp udeb debian-installer optional
 linux-udebs-powerpc64-emb udeb debian-installer optional
 linux-udebs-powerpc64-smp udeb debian-installer optional
 md-modules-3.13.0-54-generic-di udeb debian-installer standard
 message-modules-3.13.0-54-generic-di udeb debian-installer standard
 mouse-modules-3.13.0-54-generic-di udeb debian-installer extra
 multipath-modules-3.13.0-54-generic-di udeb debian-installer extra
 nfs-modules-3.13.0-54-generic-di udeb debian-installer standard
 nic-modules-3.13.0-54-generic-di udeb debian-installer standard
 nic-pcmcia-modules-3.13.0-54-generic-di udeb debian-installer standard
 nic-shared-modules-3.13.0-54-generic-di udeb debian-installer standard
 nic-usb-modules-3.13.0-54-generic-di udeb debian-installer standard
 parport-modules-3.13.0-54-generic-di udeb debian-installer standard
 pata-modules-3.13.0-54-generic-di udeb debian-installer standard
 pcmcia-modules-3.13.0-54-generic-di udeb debian-installer standard
 pcmcia-storage-modules-3.13.0-54-generic-di udeb debian-installer standard
 plip-modules-3.13.0-54-generic-di udeb debian-installer standard
 ppp-modules-3.13.0-54-generic-di udeb debian-installer standard
 sata-modules-3.13.0-54-generic-di udeb debian-installer standard
 scsi-modules-3.13.0-54-generic-di udeb debian-installer standard
 serial-modules-3.13.0-54-generic-di udeb debian-installer standard
 speakup-modules-3.13.0-54-generic-di udeb debian-installer extra
 squashfs-modules-3.13.0-54-generic-di udeb debian-installer extra
 storage-core-modules-3.13.0-54-generic-di udeb debian-installer standard
 usb-modules-3.13.0-54-generic-di udeb debian-installer standard
 virtio-modules-3.13.0-54-generic-di udeb debian-installer standard
 vlan-modules-3.13.0-54-generic-di udeb debian-installer extra
Checksums-Sha1: 
 769d3e9207f796560b56b363779290a544e2e5cc 116419243 linux_3.13.0.orig.tar.gz
 2f2c3fcf1c35c8563156f2458fda098dc053ed65 5529672 linux_3.13.0-54.91.diff.gz
Checksums-Sha256: 
 073d6a589655031564407e349c86a316941fc26ef3444bb73a092b43a48347ec 116419243 linux_3.13.0.orig.tar.gz
 729e580741fc8a925fa187732173a1f53ae59008f7df6f2581b67064039a40dc 5529672 linux_3.13.0-54.91.diff.gz
Files: 
 8c85f9d0962f2a9335028e4879b03343 116419243 linux_3.13.0.orig.tar.gz
 39a09ce09ae655cc6a3738df5c3e0644 5529672 linux_3.13.0-54.91.diff.gz
Testsuite: autopkgtest

-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iQIbBAEBAgAGBQJVZMVRAAoJENt0rrj9ziT8AbUP9jAQoAtQkbyayRqvUqGWZyO2
TYgLz7brXDoWAEqkxgwgEwSZ3WbD0fS/HNPuSdKXeKxQyKtjPLMHWa18FFWnVuE5
3WqGnzR+1lbjj73PiNL5SsP05PvQDp5M2oQlVUAcc/rfdupCw0E3mZs2JmssulpU
bdZDt2xrbt0V0d36TJYG8LsIus2HgSmmZ0UdrCQIklIqOUL8oRLVVj/T0HzOVFL0
pJ3d/ATpA+IWLCKRMvyKj5BTlb2CoRFTWi4M5xszU3l0dduNi+r+VzZnJVz/H9vF
h8miIxgPjf9qmOlACpyXiEZQgSKJa+Xcy+OhQHqaQPTEK8O/Xqy1JRmiibVrswGg
xQyypp8RzLEPYxqfWnoCpIVKI+hzEXftZWEp/9gUX7A1Y6JZKWazYQL40kC/kWYg
yPDgaxolO0lP5CMx3ZmdE3MrhDW5GmfiIM4cWaNGnDibA5Wh0Vnzfgjn1fiN0CEn
caZoPWKdvs/C8VWdOqLraoyyD8Ix/nnJH9c+2K3DK1R88KQhU44+EEipfK2qvbH7
XAiTxewREw277PcFIIZKE+gSfXsn/LxKcYftQoBP3dnHlXbHjOz4UdpfMV3TeT5C
UYahDiLcLvLlY8TNIhUroFGEcZ6uJ3DG5g79tsHloEyJ/IAVof8r2H+F4Alnc3T/
LzBa1tO/OwqjVF7HXMA=
=OfsO
-----END PGP SIGNATURE-----
