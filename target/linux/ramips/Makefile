#
# Copyright (C) 2008-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

ARCH:=mipsel
BOARD:=ramips
BOARDNAME:=MTK/Ralink APSoC (MIPS)
SUBTARGETS:=mt7620 mt7621 mt7628
FEATURES:=squashfs gpio
LINUX_VERSION:=3.10.14
LINUX_P4REV:=169495
LINUX_EXT_VERSION:=$(LINUX_VERSION)-$(LINUX_P4REV)

include $(INCLUDE_DIR)/target.mk
DEFAULT_PACKAGES += 

define Target/Description
	Build firmware images for MTK/Ralink APSoC based boards.
endef

$(eval $(call BuildTarget))
