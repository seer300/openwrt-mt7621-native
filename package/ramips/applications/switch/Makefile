#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=switch
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk


ifeq ($(CONFIG_TARGET_ramips_mt7620),y)
	TARGET_CFLAGS += -DCONFIG_RALINK_MT7620=y
	MAKE_FLAGS += CONFIG_RALINK_MT7620=y
endif

ifeq ($(CONFIG_TARGET_ramips_mt7621),y)
	TARGET_CFLAGS += -DCONFIG_RALINK_MT7621=y
	MAKE_FLAGS += CONFIG_RALINK_MT7621=y
endif

ifeq ($(CONFIG_TARGET_ramips_mt7628),y)
	TARGET_CFLAGS += -DCONFIG_RALINK_MT7628=y
	MAKE_FLAGS += CONFIG_RALINK_MT7628=y
endif

ifeq ($(CONFIG_TARGET_mediatek_mt7623_emmc),y)
	TARGET_CFLAGS += -DCONFIG_ARCH_MT7623=y
	MAKE_FLAGS += CONFIG_ARCH_MT7623=y
endif

ifeq ($(CONFIG_TARGET_mediatek_mt7623_mtd),y)
	TARGET_CFLAGS += -DCONFIG_ARCH_MT7623=y
	MAKE_FLAGS += CONFIG_ARCH_MT7623=y
endif

define Package/switch
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:=Command to config switch
  SUBMENU:=Applications
endef

define Package/switch/description
  An program to config switch.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += \
	-I$(LINUX_DIR)/drivers/net/raeth

define Build/Configure
endef

define Package/switch/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/lib/network
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/switch $(1)/usr/bin
ifeq ($(CONFIG_TARGET_ramips_mt7620),y)
	$(INSTALL_BIN) ./files/switch-7620.sh $(1)/lib/network/switch.sh
endif
ifeq ($(CONFIG_TARGET_ramips_mt7628),y)
	$(INSTALL_BIN) ./files/switch-7628.sh $(1)/lib/network/switch.sh
endif
ifeq ($(CONFIG_TARGET_ramips_mt7688),y)
	$(INSTALL_BIN) ./files/switch-7628.sh $(1)/lib/network/switch.sh
endif
ifeq ($(CONFIG_TARGET_ramips_mt7621),y)
	$(INSTALL_BIN) ./files/switch-7621.sh $(1)/lib/network/switch.sh
endif
ifeq ($(CONFIG_TARGET_mediatek_mt7623_emmc),y)
	$(INSTALL_BIN) ./files/switch-7623.sh $(1)/lib/network/switch.sh
endif
ifeq ($(CONFIG_TARGET_mediatek_mt7623_mtd),y)
	$(INSTALL_BIN) ./files/switch-7623.sh $(1)/lib/network/switch.sh
endif
endef

$(eval $(call BuildPackage,switch))
