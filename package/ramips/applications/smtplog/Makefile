#
# hua.shao@mediatek.com
#
# MTK Property Software.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=smtplog
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/smtplog
  SECTION:=MTK Properties
  CATEGORY:=MTK Properties
  DEPENDS:=+lua +luasocket +uci +libuci-lua
  TITLE:=Collect logs by email.
  SUBMENU:=Applications
endef

define Package/Compile/Default

endef
Build/Compile = $(Package/Compile/Default)

define Package/smtplog/description
  Collect logs and sent to an email address.
  For user privacy concern, do NOT abuse it.
endef

define Package/smtplog/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/etc/config/
	$(INSTALL_BIN) ./src/smtplog.sh $(1)/etc/init.d/smtplog
	$(INSTALL_BIN) ./src/smtplog.lua $(1)/usr/bin/smtplog
	$(INSTALL_BIN) ./src/smtplog.conf $(1)/etc/config/smtplog
endef

$(eval $(call BuildPackage,smtplog))

