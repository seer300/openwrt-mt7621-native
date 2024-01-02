#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define KernelPackage/usb-rt305x-dwc_otg
  TITLE:=RT305X USB controller driver
  DEPENDS:=@TARGET_ramips_rt305x
  KCONFIG:= \
	CONFIG_DWC_OTG \
	CONFIG_DWC_OTG_HOST_ONLY=y \
	CONFIG_DWC_OTG_DEVICE_ONLY=n \
	CONFIG_DWC_OTG_DEBUG=n
  FILES:=$(LINUX_DIR)/drivers/usb/dwc_otg/dwc_otg.ko
  AUTOLOAD:=$(call AutoLoad,54,dwc_otg,1)
  $(call AddDepends/usb)
endef

define KernelPackage/usb-rt305x-dwc_otg/description
 This driver provides USB Device Controller support for the
 Synopsys DesignWare USB OTG Core used in the Ralink RT305X SoCs.
endef

$(eval $(call KernelPackage,usb-rt305x-dwc_otg))

OTHER_MENU:=Other modules
define KernelPackage/sdhci-mt7620
  SUBMENU:=Other modules
  TITLE:=MT7620 SDCI
  DEPENDS:=@TARGET_ramips_mt7620a +kmod-sdhci
  KCONFIG:= \
	CONFIG_MMC_SDHCI_MT7620
  FILES:= \
	$(LINUX_DIR)/drivers/mmc/host/sdhci-mt7620.ko
  AUTOLOAD:=$(call AutoProbe,sdhci-mt7620,1)
endef

$(eval $(call KernelPackage,sdhci-mt7620))

I2C_RALINK_MODULES:= \
  CONFIG_I2C_RALINK:drivers/i2c/busses/i2c-ralink

define KernelPackage/i2c-ralink
  $(call i2c_defaults,$(I2C_RALINK_MODULES),59)
  TITLE:=Ralink I2C Controller
  DEPENDS:=@TARGET_ramips kmod-i2c-core
endef

define KernelPackage/i2c-ralink/description
 Kernel modules for enable ralink i2c controller.
endef

$(eval $(call KernelPackage,i2c-ralink))


define KernelPackage/hw_nat
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=MTK Hardware NAT
  KCONFIG:=CONFIG_RA_HW_NAT
  DEPENDS:=@TARGET_ramips_mt7620||@TARGET_ramips_mt7621||@TARGET_mediatek_mt7623_emmc||@TARGET_mediatek_mt7623_mtd
  FILES:=$(LINUX_DIR)/net/nat/hw_nat/hw_nat.ko
  AUTOLOAD:=$(call AutoProbe,hw_nat)
endef

define KernelPackage/hw_nat/install
	$(INSTALL_DIR) $(1)/lib/modules/ralink/
	mv $(1)/lib/modules/$(if $(findstring y,$(CONFIG_TARGET_mediatek)),3.10.20,3.10.14)/hw_nat.ko $(1)/lib/modules/ralink/
endef

$(eval $(call KernelPackage,hw_nat))

define KernelPackage/nf-sc
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=Netfilter shortcut
  DEPENDS:=+kmod-ipt-core
  KCONFIG:=CONFIG_NF_SHORTCUT_HOOK
  FILES:=$(LINUX_DIR)/net/netfilter/nf_sc.ko
  AUTOLOAD:=$(call AutoProbe,nf_sc)
endef

define KernelPackage/nf-sc/install
	$(INSTALL_DIR) $(1)/lib/modules/ralink/
	mv $(1)/lib/modules/$(if $(findstring y,$(CONFIG_TARGET_mediatek)),3.10.20,3.10.14)/nf_sc.ko $(1)/lib/modules/ralink/
endef

define KernelPackage/nf-sc/description
 Kernel modules support for shortcut
endef

$(eval $(call KernelPackage,nf-sc))

define KernelPackage/sound-mt7620
  TITLE:=MT7620 PCM/I2S Alsa Driver
  DEPENDS:=@TARGET_ramips_mt7620a +kmod-sound-soc-core +kmod-regmap
  KCONFIG:= \
	CONFIG_SND_MT7620_SOC_I2S \
	CONFIG_SND_MT7620_SOC_WM8960
  FILES:= \
	$(LINUX_DIR)/sound/soc/ralink/snd-soc-mt7620-i2s.ko \
	$(LINUX_DIR)/sound/soc/ralink/snd-soc-mt7620-wm8960.ko \
	$(LINUX_DIR)/sound/soc/codecs/snd-soc-wm8960.ko
  AUTOLOAD:=$(call AutoLoad,90,snd-soc-wm8960 snd-soc-mt7620-i2s snd-soc-mt7620-wm8960)
  $(call AddDepends/sound)
endef

define KernelPackage/sound-mt7620/description
 Alsa modules for ralink i2s controller.
endef

$(eval $(call KernelPackage,sound-mt7620))



define KernelPackage/mtk-gdma
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=GDMA Driver
  DEPENDS:=@TARGET_ramips_mt7621
  KCONFIG:=CONFIG_RALINK_GDMA CONFIG_GDMA_EVERYBODY
  FILES:=$(LINUX_DIR)/drivers/char/ralink_gdma.ko
  AUTOLOAD:=$(call AutoLoad,90,ralink_gdma)
endef

define KernelPackage/mtk-gdma/description
  MediaTek APSoC GDMA driver
endef

$(eval $(call KernelPackage,mtk-gdma))



define KernelPackage/mtk-i2c
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=MTK I2C Driver
  DEPENDS:=@TARGET_ramips_mt7621
  KCONFIG:=CONFIG_RALINK_I2C
  FILES:=$(LINUX_DIR)/drivers/char/i2c_drv.ko
  AUTOLOAD:=$(call AutoLoad,90,i2c_drv)
endef

define KernelPackage/mtk-i2c/description
  MediaTek APSoC I2C Driver
endef

$(eval $(call KernelPackage,mtk-i2c))


define KernelPackage/mtk-pcm
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=MTK PCM Driver
  DEPENDS:=@TARGET_ramips_mt7621 +kmod-mtk-gdma
  KCONFIG:=CONFIG_RALINK_PCM
  FILES:=$(LINUX_DIR)/drivers/char/pcm/ralink_pcm.ko
  AUTOLOAD:=$(call AutoLoad,90,ralink_pcm)
endef

define KernelPackage/mtk-pcm/description
  MediaTek APSoC PCM Driver
endef

$(eval $(call KernelPackage,mtk-pcm))


define KernelPackage/mtk-i2s
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=I2S Driver
  DEPENDS:=@TARGET_ramips_mt7621 +kmod-mtk-gdma +kmod-mtk-i2c
  KCONFIG:=CONFIG_RALINK_I2S CONFIG_I2S_WM8960
  FILES:=$(LINUX_DIR)/drivers/char/i2s/core/ralink_i2s.ko
  AUTOLOAD:=$(call AutoLoad,90,ralink_i2s)
endef

define KernelPackage/mtk-i2s/description
  MediaTek APSoC I2S driver, along with a WM8960 driver (You don't
  have to choose /sound/soc/codecs/wm8960 .
endef

$(eval $(call KernelPackage,mtk-i2s))



define KernelPackage/mtk-mmc
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=MMC/SD card support
  DEPENDS:=+kmod-mmc
  KCONFIG:= \
	CONFIG_MTK_MMC=m
  FILES:= \
    $(LINUX_DIR)/drivers/mmc/host/mtk-mmc/mtk_sd.ko
  AUTOLOAD:=$(call AutoLoad,90,mtk_sd)
endef

define KernelPackage/mtk-mmc/description
  driver for mtk mmc/sd card controller.
endef

$(eval $(call KernelPackage,mtk-mmc))


define KernelPackage/hw_wdg
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=MTK APSoC Watchdog Driver
  KCONFIG:= CONFIG_WATCHDOG=y CONFIG_RALINK_WATCHDOG CONFIG_RALINK_TIMER_WDG_RESET_OUTPUT=y
  FILES:=$(LINUX_DIR)/drivers/watchdog/ralink_wdt.ko
  AUTOLOAD:=$(call AutoProbe,ralink_wdt)
endef

$(eval $(call KernelPackage,hw_wdg))

define KernelPackage/hw_kwdg
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=Kernel Mode Watchdog
  KCONFIG:=CONFIG_RALINK_TIMER CONFIG_RALINK_TIMER_DFS=y CONFIG_RALINK_TIMER_WDG CONFIG_RALINK_WDG_TIMER=10 CONFIG_RALINK_WDG_REFRESH_INTERVAL=4 CONFIG_RALINK_TIMER_WDG_RESET_OUTPUT=y
  FILES:=$(LINUX_DIR)/arch/mips/ralink/ralink_wdt.ko
  AUTOLOAD:=$(call AutoProbe,ralink_wdt)
endef

$(eval $(call KernelPackage,hw_kwdg))


define KernelPackage/rdm
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=Register Debug Module
  KCONFIG:=CONFIG_RALINK_RDM=m
  FILES:=$(LINUX_DIR)/drivers/net/rt_rdm/rt_rdm.ko
  AUTOLOAD:=$(call AutoProbe,rt_rdm)
endef

$(eval $(call KernelPackage,rdm))


define KernelPackage/cfg80211-normal
  CATEGORY:=MTK Properties
  SUBMENU:=Drivers
  TITLE:=CFG80211 kernel support
  KCONFIG:=CONFIG_CFG80211=m
  FILES:=$(LINUX_DIR)/net/wireless/cfg80211.ko
  AUTOLOAD:=$(call AutoProbe,cfg80211)
endef

$(eval $(call KernelPackage,cfg80211-normal))


