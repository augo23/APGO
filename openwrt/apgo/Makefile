# APGO overlay client — OpenWrt package.
#
# Build with the OpenWrt SDK (or a full buildroot) for your router's target:
#
#   cp -r openwrt/apgo <sdk>/package/apgo
#   cd <sdk>
#   ./scripts/feeds update -a && ./scripts/feeds install -a   # for golang.mk
#   make defconfig
#   make package/apgo/compile V=s
#
# The resulting .ipk lands in bin/packages/<arch>/base/. See ../README.md.
#
# PKG_SOURCE fetches a tagged release from GitHub. To build straight from
# your working tree instead, uncomment USE_SOURCE_DIR below and point it at
# the repo root.

include $(TOPDIR)/rules.mk

PKG_NAME:=apgo
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/augo23/APGO/tar.gz/v$(PKG_VERSION)?
# Fill in after the first download attempt prints the real hash
# (or set PKG_HASH:=skip for local experiments):
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/APGO-$(PKG_VERSION)

# Build straight from a local checkout instead of a release tarball:
# USE_SOURCE_DIR:=/path/to/P2P-Overlay-Network

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=The APGO Team

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=overlay-overlay/client
GO_PKG_BUILD_PKG:=overlay-overlay/client
GO_PKG_LDFLAGS:=-s -w

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/apgo
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=APGO — self-organizing encrypted P2P overlay network
  URL:=https://www.apgoverlay.com
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-tun +ca-bundle
endef

define Package/apgo/description
  APGO (Another Pretty Good Overlay) joins this router to a self-organizing,
  end-to-end encrypted peer-to-peer overlay network — quantum-safe by
  default, no central server, no account. Same client as the Docker image.
  Configure in /etc/config/apgo (UCI); service: /etc/init.d/apgo.
endef

# The Go module lives in client/ inside the repo tarball.
define Build/Prepare
	$(call Build/Prepare/Default)
	( cd $(PKG_BUILD_DIR) && [ -d client ] && cp -r client/* . || true )
endef

define Package/apgo/conffiles
/etc/config/apgo
endef

define Package/apgo/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/client $(1)/usr/bin/overlay-client
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/apgo.init $(1)/etc/init.d/apgo
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/apgo.config $(1)/etc/config/apgo
endef

$(eval $(call GoBinPackage,apgo))
$(eval $(call BuildPackage,apgo))
