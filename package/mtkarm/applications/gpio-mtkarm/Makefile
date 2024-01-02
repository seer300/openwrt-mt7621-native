#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=gpio-mtkarm
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_KCONFIG:=RALINK_MT7623
PKG_CONFIG_DEPENDS:=$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)))


include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/gpio-mtkarm
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:=Command to config gpio (mtkarm, 7623)
  DEPENDS:=@TARGET_mediatek
  SUBMENU:=Applications
endef

define Package/gpio-mtkarm/description
  An program to config gpio.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += \
	-I$(LINUX_DIR)/arch/arm/include \
	-I$(LINUX_DIR)/arch/mach-arm/include \
	-I$(LINUX_DIR)/include \
	-I$(LINUX_DIR)/drivers/char \
	$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),-DCONFIG_$(c)))

define Build/Configure
endef

define Package/gpio-mtkarm/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/gpio $(1)/usr/bin
endef


$(eval $(call BuildPackage,gpio-mtkarm))

