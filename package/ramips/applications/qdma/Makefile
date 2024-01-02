#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=qdma
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=RALINK_MT7621

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/qdma
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  DEPENDS:=@(TARGET_ramips_mt7621||TARGET_mediatek_mt7623_emmc||TARGET_mediatek_mt7623_mtd)
  TITLE:=QDMA configuration tool
  SUBMENU:=Applications
endef

define Package/qdma/description
  QDMA configuration tool
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


TARGET_CFLAGS += -I$(LINUX_DIR)/drivers/net/raeth
TARGET_CFLAGS += $(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),-DCONFIG_$(c)=$(CONFIG_$c)))
TARGET_CFLAGS += -Wall
TARGET_CFLAGS += -Wno-error=format-security 

define Build/Configure
endef

define Package/qdma/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/qdma $(1)/usr/bin
endef


$(eval $(call BuildPackage,qdma))

