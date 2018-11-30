include $(TOPDIR)/rules.mk

PKG_NAME:=sysu-h3c
PKG_VERSION:=v0.1.0
PKG_RELEASE=1
PKG_REV:=fe2aaac3989ae8f0ff1b952c7d6f98b3b60ec4fb

PKG_SOURCE_URL:=https://github.com/KryptonLee/sysu-h3c.git
PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

PKG_LICENSE:=GPL-3.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=Krypton Lee <jun.k.lee199410@outlook.com>

include $(INCLUDE_DIR)/package.mk

define Package/sysu-h3c
  SECTION:=net
  CATEGORY:=Network
  TITLE:=H3C 802.1X authentication client for SYSU east campus
  URL:=https://github.com/KryptonLee/sysu-h3c
endef

define Package/sysu-h3c/install
        $(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/sysu-h3c $(1)/usr/bin/
endef

$(eval $(call BuildPackage,sysu-h3c))