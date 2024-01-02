# All rights reserved.
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mt7628sta
P4REV:=130908
PKG_VERSION:=4.0.1.4
PKG_SOURCE:=MT7628-STA-4.0.1.4.tar.bz2
PKG_SOURCE_URL:=http://localhost/
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_KCONFIG:=RALINK_MT7628 \
	MT_WIFI \
	FIRST_IF_EEPROM_PROM \
	FIRST_IF_EEPROM_EFUSE \
	FIRST_IF_EEPROM_FLASH \
	RT_FIRST_CARD_EEPROM \
	SECOND_IF_EEPROM_PROM \
	SECOND_IF_EEPROM_EFUSE \
	SECOND_IF_EEPROM_FLASH \
	RT_SECOND_CARD_EEPROM \
	MULTI_INF_SUPPORT \
	WIFI_BASIC_FUNC \
	MT7628_WSC_INCLUDED \
	MT7628_WSC_V2_SUPPORT \
	MT7628_DOT11W_PMF_SUPPORT \
	MT7628_LLTD_SUPPORT \
	MT7628_QOS_DLS_SUPPORT \
	MT7628_IGMP_SNOOP_SUPPORT \
	MT7628_BLOCK_NET_IF \
	MT7628_RATE_ADAPTION \
	MT7628_NEW_RATE_ADAPT_SUPPORT \
	MT7628_AGS_SUPPORT \
	MT7628_IDS_SUPPORT \
	MT7628_WIFI_WORKQUEUE \
	MT7628_WIFI_SKB_RECYCLE \
	MT7628_SMART_CARRIER_SENSE_SUPPORT \
	MT7628_LED_CONTROL_SUPPORT \
	MT7628_ATE_SUPPORT \
	MT7628_MEMORY_OPTIMIZATION \
	MT7628_PASSPOINT_R2 \
	MT7628_SINGLE_SKU \
	MT7628_UAPSD \
	MT_MAC \
	RTMP_PCI_SUPPORT \
	RTMP_USB_SUPPORT \
	RTMP_RBUS_SUPPORT \
	MT_WIFI_MODE_AP \
	MT_WIFI_MODE_STA \
	MT_WIFI_MODE_BOTH \
	MT_AP_SUPPORT \
	MT_STA_SUPPORT 

include $(INCLUDE_DIR)/package.mk

TAR_CMD=$(HOST_TAR) -C $(1)/ $(TAR_OPTIONS)

define KernelPackage/mt7628sta
  CATEGORY:=MTK Properties
  TITLE:=MTK MT7628 wifi STA driver
  FILES:=$(PKG_BUILD_DIR)/mt_wifi_sta/mt7628sta.ko
  AUTOLOAD:=$(call AutoLoad,90,mt7628sta)
  DEPENDS:=@TARGET_ramips_mt7628 +kmod-cfg80211-normal +wpa-supplicant-20
  SUBMENU:=Drivers
  MENU:=1
endef

define KernelPackage/mt7628sta/config
	source "$(SOURCE)/config.in"
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" V=1 \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		SUBDIRS="$(PKG_BUILD_DIR)/mt_wifi_sta/" \
		$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)=$(CONFIG_$(c)))) \
		modules
endef

define P4/Info
  P4URL:=//Jedi/MP/jedi.MT7628.MP/wifi_driver/
endef

define P4/Release
  echo "Gone with the wind."
endef

define KernelPackage/mt7628sta/install
	$(INSTALL_DIR) $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/mt7628sta.sh $(1)/lib/wifi/
	$(INSTALL_BIN) ./files/wpa_supplicant.sh $(1)/lib/wifi/
	$(INSTALL_DIR) $(1)/etc/wireless/mt7628sta/
	$(INSTALL_BIN) ./files/mt7628sta.dat $(1)/etc/wireless/mt7628sta/
	#-if [ "$$(CONFIG_INTERNAL_PA_INTERNAL_LNA)" = "y" ]; then \
	#	$(INSTALL_BIN) ./files/mt7628sta.eeprom.ipa.ilna.bin $(1)/etc/wireless/mt7628sta/mt7628sta.eeprom.bin; \
	#elif [ "$$(CONFIG_INTERNAL_PA_EXTERNAL_LNA)" = "y" ]; then \
	#	$(INSTALL_BIN) ./files/mt7628sta.eeprom.ipa.elna.bin $(1)/etc/wireless/mt7628sta/mt7628sta.eeprom.bin; \
	#elif [ "$$(CONFIG_EXTERNAL_PA_EXTERNAL_LNA)" = "y" ]; then \
	#	$(INSTALL_BIN) ./files/mt7628sta.eeprom.epa.elna.bin $(1)/etc/wireless/mt7628sta/mt7628sta.eeprom.bin; \
	#else \
	#	$(INSTALL_BIN) ./files/mt7628sta.eeprom.ipa.elna.bin $(1)/etc/wireless/mt7628sta/mt7628sta.eeprom.bin; \
	#fi
	echo $(PKG_VERSION) > $(1)/etc/wireless/mt7628sta/version
endef

$(eval $(call KernelPackage,mt7628sta))
