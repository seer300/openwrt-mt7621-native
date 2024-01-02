#
# Copyright (C) 2015 MediaTek
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Profile/MT7623_MTD
    NAME:=Default Profile
    PACKAGES:=\
        -swconfig -rt2x00 \
        ated hwnat switch uci2dat mii_mgr 8021xd e2fsprogs luci mpstat reg nvram qdma \
        wireless-tools block-mount fstools kmod-scsi-generic \
        kmod-nf-sc \
        kmod-usb-core kmod-usb-storage \
        kmod-fs-vfat kmod-fs-ext4 kmod-fs-ntfs \
        kmod-nls-base kmod-nls-utf8 kmod-nls-cp936 \
        kmod-nls-cp437 kmod-nls-cp850 kmod-nls-iso8859-1 kmod-nls-iso8859-15 kmod-nls-cp950
endef


define Profile/MT7623_MTD/Description
	Basic MT7623 SoC support
endef
$(eval $(call Profile,MT7623_MTD))


