#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pcmtest
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_CONFIG_DEPENDS:=

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

define Package/pcmtest
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  TITLE:=PCM Test Command
  SUBMENU:=Applications
  DEPENDS:=+kmod-mtk-pcm
endef

define Package/pcmtest/description
  An program to test PCM driver and interface. 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

TARGET_CFLAGS += \
	-I$(LINUX_DIR)/drivers/char/pcm

MAKE_FLAGS += \
	CFLAGS="$(TARGET_CFLAGS)"


define Build/Configure
endef

define Package/pcmtest/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pcmtest $(1)/usr/bin
endef


$(eval $(call BuildPackage,pcmtest))

