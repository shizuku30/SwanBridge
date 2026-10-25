# Derived from OpenWrt packages 093d551675b1119a06ef224d419905e8d6b2af1a.
# GPL-2.0-or-later. This build intentionally supports IKEv2 PSK only.
include $(TOPDIR)/rules.mk

PKG_NAME:=strongswan
PKG_VERSION:=6.1.0
PKG_RELEASE:=2
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://download.strongswan.org/
PKG_HASH:=d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963
PKG_LICENSE:=GPL-2.0-or-later
PKG_LICENSE_FILES:=COPYING
PKG_CPE_ID:=cpe:/a:strongswan:strongswan
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1
PKG_MOD_AVAILABLE:=aes attr gcm gmp hmac kdf kernel-netlink random sha1 sha2 socket-default vici xcbc
PKG_CONFIG_DEPENDS:=$(patsubst %,CONFIG_PACKAGE_strongswan-mod-%,$(PKG_MOD_AVAILABLE))

include $(INCLUDE_DIR)/package.mk

define Package/strongswan/Default
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=strongSwan
  URL:=https://www.strongswan.org/
endef

define Package/strongswan
$(call Package/strongswan/Default)
  TITLE+= shared libraries (SwanBridge IKEv2 PSK build)
  DEPENDS:=+libpthread +ip +kmod-ipsec +kmod-ipsec4 +kmod-crypto-aead +kmod-crypto-authenc +kmod-crypto-cbc +kmod-crypto-hmac +kmod-crypto-sha256 +kmod-crypto-sha512 +kmod-crypto-gcm +kmod-crypto-echainiv
endef

define Package/strongswan-charon
$(call Package/strongswan/Default)
  TITLE+= IKEv2 daemon
  DEPENDS:=strongswan
  EXTRA_DEPENDS:=strongswan (=$(PKG_VERSION)-r$(PKG_RELEASE))
endef

define Package/strongswan-swanctl
$(call Package/strongswan/Default)
  TITLE+= swanctl control utility
  DEPENDS:=strongswan +strongswan-mod-vici
  EXTRA_DEPENDS:=strongswan (=$(PKG_VERSION)-r$(PKG_RELEASE))
endef

CONFIGURE_ARGS+= \
  --disable-defaults --disable-static --disable-fast --disable-scripts \
  --enable-charon --enable-ikev2 --enable-swanctl --enable-nonce --enable-mgf1 \
  --disable-python-wheels --disable-python-eggs --with-systemdsystemunitdir=no \
  --with-random-device=/dev/random --with-urandom-device=/dev/urandom \
  --with-routing-table=220 --with-routing-table-prio=220 \
  $(foreach m,$(PKG_MOD_AVAILABLE),$(if $(CONFIG_PACKAGE_strongswan-mod-$(m)),--enable-$(m),--disable-$(m))) \
  ac_cv_search___atomic_load=no

define Package/strongswan/conffiles
/etc/strongswan.conf
/etc/strongswan.d/
endef

define Package/strongswan/install
	$(INSTALL_DIR) $(1)/etc/strongswan.d/charon $(1)/usr/lib/ipsec/plugins
	$(INSTALL_CONF) $(PKG_INSTALL_DIR)/etc/strongswan.conf $(1)/etc/
	printf '\ninclude /var/ipsec/strongswan.conf\n' >> $(1)/etc/strongswan.conf
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/etc/strongswan.d/charon/nonce.conf $(1)/etc/strongswan.d/charon/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/etc/strongswan.d/charon/mgf1.conf $(1)/etc/strongswan.d/charon/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/libstrongswan.so.* $(1)/usr/lib/ipsec/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/plugins/libstrongswan-nonce.so $(1)/usr/lib/ipsec/plugins/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/plugins/libstrongswan-mgf1.so $(1)/usr/lib/ipsec/plugins/
endef

define Package/strongswan-charon/conffiles
/etc/strongswan.d/charon.conf
/etc/strongswan.d/charon-logging.conf
endef

define Package/strongswan-charon/install
	$(INSTALL_DIR) $(1)/etc/strongswan.d $(1)/usr/lib/ipsec
	$(CP) $(PKG_INSTALL_DIR)/etc/strongswan.d/charon{,-logging}.conf $(1)/etc/strongswan.d/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/ipsec/charon $(1)/usr/lib/ipsec/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/libcharon.so.* $(1)/usr/lib/ipsec/
endef

define Package/strongswan-swanctl/conffiles
/etc/config/ipsec
/etc/swanctl/
endef

define Package/strongswan-swanctl/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/swanctl/{conf.d,ecdsa,pkcs{12,8},private,pubkey,rsa}
	$(INSTALL_DIR) $(1)/etc/swanctl/x509{,aa,ac,ca,crl,ocsp}
	$(CP) $(PKG_INSTALL_DIR)/etc/swanctl/swanctl.conf $(1)/etc/swanctl/
	printf '\ninclude /var/swanctl/swanctl.conf\n' >> $(1)/etc/swanctl/swanctl.conf
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/swanctl $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/swanctl.init $(1)/etc/init.d/swanctl
	$(INSTALL_CONF) ./files/ipsec.config $(1)/etc/config/ipsec
endef

define BuildPlugin
  define Package/strongswan-mod-$(1)
    $$(call Package/strongswan/Default)
    TITLE+= $(1) plugin
    DEPENDS:=strongswan $(2)
    EXTRA_DEPENDS:=strongswan (=$(PKG_VERSION)-r$(PKG_RELEASE))
  endef

  define Package/strongswan-mod-$(1)/conffiles
/etc/strongswan.d/charon/$(1).conf
  endef

  define Package/strongswan-mod-$(1)/install
	$(INSTALL_DIR) $$(1)/etc/strongswan.d/charon $$(1)/usr/lib/ipsec/plugins
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/etc/strongswan.d/charon/$(1).conf $$(1)/etc/strongswan.d/charon/
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/plugins/libstrongswan-$(1).so $$(1)/usr/lib/ipsec/plugins/
	$(if $(filter vici,$(1)),$(CP) $(PKG_INSTALL_DIR)/usr/lib/ipsec/libvici.so.* $$(1)/usr/lib/ipsec/)
  endef

  $$(eval $$(call BuildPackage,strongswan-mod-$(1)))
endef

$(eval $(call BuildPackage,strongswan))
$(eval $(call BuildPackage,strongswan-charon))
$(eval $(call BuildPackage,strongswan-swanctl))
$(foreach m,$(PKG_MOD_AVAILABLE),$(eval $(call BuildPlugin,$(m),$(if $(filter gmp,$(m)),+libgmp))))
