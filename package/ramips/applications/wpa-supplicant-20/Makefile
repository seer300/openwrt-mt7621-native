#
# Copyright (C) 2015 MediTek.inc 
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wpa-supplicant-20
PKG_VERSION:=2.0
PKG_RELEASE:=0
PKG_SOURCE_URL:=http://w1.fi/releases/
PKG_SOURCE:=wpa_supplicant-2.0.tar.gz
PKG_MAINTAINER:=Hua Shao <hua.shao@mediatek.com>
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DIR2:=$(PKG_BUILD_DIR)/wpa_supplicant-2.0

include $(INCLUDE_DIR)/package.mk
TAR_CMD=$(HOST_TAR) -C $(1)/ $(TAR_OPTIONS)

define Package/wpa-supplicant-20
  CATEGORY:=MTK Properties
  SUBMENU:=Applications
  TITLE:=WPA Supplicant V2.0
  DEPENDS:=+libnl
endef

define Package/wpa-supplicant-20/description
  WPA Supplicant V2.0
endef

CONFIGURE_VARS += \
	LIBDBI_CFLAGS="-I$(STAGING_DIR)/usr/include"

ifneq ($(wildcard $(PKG_BUILD_DIR2)/.config_*),$(subst .configured_,.config_,$(STAMP_CONFIGURED)))
  define Build/Configure/rebuild
	$(FIND) $(PKG_BUILD_DIR2) -name \*.o -or -name \*.a | $(XARGS) rm -f
	rm -f $(PKG_BUILD_DIR2)/wpa_supplicant/wpa_supplicant
	rm -f $(PKG_BUILD_DIR2)/wpa_supplican/t.config_*
	touch $(subst .configured_,.config_,$(STAMP_CONFIGURED))
  endef
endif


define Build/Configure
	$(Build/Configure/rebuild)
	$(CP) ./files/wpa_supplicant-mini.config $(PKG_BUILD_DIR2)/wpa_supplicant/.config
endef

DRIVER_MAKEOPTS= \
    CONFIG_DRIVER_NL80211=y \
    CONFIG_IEEE80211N=$(HOSTAPD_IEEE80211N)

TARGET_CPPFLAGS += \
    -I$(PKG_BUILD_DIR2)/src \
    -I$(PKG_BUILD_DIR2)/src/utils \
    -I$(LINUX_DIR)/include \
    -I$(STAGING_DIR)/usr/include/libnl3 \
    -DCONFIG_LIBNL20 \
    -D_GNU_SOURCE \
    -DCONFIG_MSG_MIN_PRIORITY=0

TARGET_CFLAGS += \
	-ffunction-sections \
	-fdata-sections \
	-DNO_TIMESTAMP_CHECK

TARGET_LDFLAGS += -Wl,--gc-sections -lnl-3 -lnl-genl-3 -lnl-nf-3 -lnl-route-3
TARGET_CONFIGURE_OPTS += CONFIG_P2P=y CONFIG_INTERNAL_LIBTOMMATH=y

#define Build/Compile
#	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR2)/wpa_supplicant V=2 \
#		$(TARGET_CONFIGURE_OPTS) \
#		$(DRIVER_MAKEOPTS) \
#		CFLAGS="$(TARGET_CPPFLAGS)" \
#		CROSS_COMPILE="$(TARGET_CROSS)" \
#		$(foreach c, $(PKG_KCONFIG),$(if $(CONFIG_$c),CONFIG_$(c)=y)) \
#		LIBS="$(TARGET_CFLAGS)" \
#		BCHECK= \
#		wpa_supplicant
#endef


define Build/RunMake
	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR2)/$(1) \
		$(TARGET_CONFIGURE_OPTS) \
		$(DRIVER_MAKEOPTS) \
		LIBS="$(TARGET_LDFLAGS)" \
		LIBS_c="$(TARGET_LDFLAGS_C)" \
		BCHECK= \
		$(2)
endef

define Build/Compile/wpad
	echo ` \
		$(call Build/RunMake,wpa_supplicant,-s MULTICALL=1 dump_cflags) | \
		sed -e 's,-n ,,g' -e 's,$(TARGET_CFLAGS),,' \
	` > $(PKG_BUILD_DIR)/.cflags
	+$(call Build/RunMake,hostapd, \
		CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		MULTICALL=1 \
		hostapd_cli hostapd_multi.a \
	)
	+$(call Build/RunMake,wpa_supplicant, \
		CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
		MULTICALL=1 \
		wpa_cli wpa_supplicant_multi.a \
	)
	$(TARGET_CC) -o $(PKG_BUILD_DIR)/wpad \
		$(TARGET_CFLAGS) \
		./files/multicall.c \
		$(PKG_BUILD_DIR)/hostapd/hostapd_multi.a \
		$(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant_multi.a \
		$(TARGET_LDFLAGS)
endef


define Build/Compile
    $(call Build/RunMake,wpa_supplicant, \
        wpa_cli wpa_supplicant \
    )
endef




#define Build/RunMake
#	CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS)" \
#	$(MAKE) $(PKG_JOBS) -C $(PKG_BUILD_DIR)/$(1) \
#		$(TARGET_CONFIGURE_OPTS) \
#		$(DRIVER_MAKEOPTS) \
#		LIBS="$(TARGET_LDFLAGS)" \
#		LIBS_c="$(TARGET_LDFLAGS_C)" \
#		BCHECK= \
#		$(2)
#endef
#
#define Build/Compile/wpad
#	echo ` \
#		$(call Build/RunMake,hostapd,-s MULTICALL=1 dump_cflags); \
#		$(call Build/RunMake,wpa_supplicant,-s MULTICALL=1 dump_cflags) | \
#		sed -e 's,-n ,,g' -e 's,$(TARGET_CFLAGS),,' \
#	` > $(PKG_BUILD_DIR)/.cflags
#	+$(call Build/RunMake,hostapd, \
#		CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
#		MULTICALL=1 \
#		hostapd_cli hostapd_multi.a \
#	)
#	+$(call Build/RunMake,wpa_supplicant, \
#		CFLAGS="$$$$(cat $(PKG_BUILD_DIR)/.cflags)" \
#		MULTICALL=1 \
#		wpa_cli wpa_supplicant_multi.a \
#	)
#	$(TARGET_CC) -o $(PKG_BUILD_DIR)/wpad \
#		$(TARGET_CFLAGS) \
#		./files/multicall.c \
#		$(PKG_BUILD_DIR)/hostapd/hostapd_multi.a \
#		$(PKG_BUILD_DIR)/wpa_supplicant/wpa_supplicant_multi.a \
#		$(TARGET_LDFLAGS)
#endef
#
#define Build/Compile/hostapd
#	$(call Build/RunMake,hostapd, \
#		hostapd hostapd_cli \
#	)
#endef




define Package/wpa-supplicant-20/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(CP) $(PKG_BUILD_DIR2)/wpa_supplicant/wpa_supplicant  $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR2)/wpa_supplicant/wpa_cli $(1)/usr/sbin/

	$(INSTALL_DIR) $(1)/etc
	$(CP) files/wpa_supplicant.conf $(1)/etc/
	$(CP) files/p2p_dev.conf $(1)/etc/
	$(CP) files/p2p_dhcpd.conf $(1)/etc/
endef

$(eval $(call BuildPackage,wpa-supplicant-20))

