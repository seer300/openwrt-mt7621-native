# All rights reserved.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

# need modify wifi.mk driver version
PKG_NAME:=mt7615e
PKG_VERSION:=MT7615_LinuxAP_V4.4.1.2_20170514
PKG_SOURCE:=MT7615_LinuxAP_V4.4.1.2_20170514.tar.bz2
PKG_SOURCE_URL:=http://localhost/
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/mt7615e
  CATEGORY:=MTK Properties
  TITLE:=MTK MT7615e wifi AP profile only
  SUBMENU:=Drivers
#  MENU:=1
endef

define Package/mt7615e/description
	@echo "TBD"
endef

define Build/Prepare
	@echo "this package is built with kernel"
endef

define Build/Compile
	@echo "this package is built with kernel"
endef

define Package/mt7615e/install
	$(INSTALL_DIR) $(1)/lib/wifi/
	$(INSTALL_DIR) $(1)/etc/wireless/mt7615e/
	$(INSTALL_BIN) ./files/mt7615e-sku.dat $(1)/etc/wireless/mt7615e/
	$(INSTALL_BIN) ./files/mt7615e-sku-bf.dat $(1)/etc/wireless/mt7615e/
	echo $(PKG_VERSION) > $(1)/etc/wireless/mt7615e/version
	$(INSTALL_BIN) ./files/mt7615e.inc $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/mt7615e*.sh $(1)/lib/wifi/

	if [ "$$(CONFIG_PACKAGE_mt7615e)" = "y" ]; then \
		$(INSTALL_BIN) ./files/mt7615e.1.*.dat $(1)/etc/wireless/mt7615e/; \
		$(INSTALL_BIN) ./files/mt7615e*.bin $(1)/etc/wireless/mt7615e/; \
	fi

	if [ "$$(CONFIG_KCONFIG_SECOND_IF_MT7615E)" = "y" ]; then \
		$(INSTALL_BIN) ./files/mt7615e.2.*.dat $(1)/etc/wireless/mt7615e/; \
		$(INSTALL_BIN) ./files/mt7615e*.bin $(1)/etc/wireless/mt7615e/; \
	fi

	if [ "$$(CONFIG_KCONFIG_THIRD_IF_MT7615E)" = "y" ]; then \
		$(INSTALL_BIN) ./files/mt7615e.3.*.dat $(1)/etc/wireless/mt7615e/; \
		$(INSTALL_BIN) ./files/mt7615e.3.dat $(1)/etc/wireless/mt7615e/; \
		$(INSTALL_BIN) ./files/mt7615e*.bin $(1)/etc/wireless/mt7615e/; \
	fi
endef

$(eval $(call BuildPackage,mt7615e))
