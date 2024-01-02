#
# Copyright (C) 2010-2014 hua.shao@mediatek.com
#
# MediaTek Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wapid
PKG_VERSION:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)


include $(INCLUDE_DIR)/package.mk

define Package/wapid
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:=Wapid
  SUBMENU:=Applications
  DEPENDS:=@TARGET_ramips +libc +libopenssl
endef

define Package/wapid/description
  wapid tool
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include/

MAKE_FLAGS += \
        CFLAGS="$(TARGET_CFLAGS)"


define Package/wapid/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wapid $(1)/usr/bin
endef


$(eval $(call BuildPackage,wapid))

