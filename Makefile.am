NULL =
SUBDIRS= \
	src \
	po \
	pam \
	data \
	$(NULL)

lxdm_confdir = /etc/lxdm
lxdm_conf_DATA = \
	data/lxdm.conf \
	data/Xsession \
	$(NULL)

lxdm_pamdir = /etc/pam.d
lxdm_pam_DATA = \
	pam/lxdm \
	$(NULL)

lxdm_bindir = /usr/bin
lxdm_bin_DATA = \
	data/lxdm

lxdmdir = $(datadir)/lxdm
lxdm_DATA = \
	data/lxdm.glade \
	$(NULL)

install-data-hook:
	chmod +x $(DESTDIR)/etc/lxdm/Xsession
	chmod +x $(DESTDIR)/usr/bin/lxdm

rpm: dist @PACKAGE_NAME@.spec
	rpmbuild -bb \
	--define "_sourcedir `pwd`" \
	--define "_builddir `pwd`" \
	--define "_srcrpmdir `pwd`" \
	--define "_rpmdir `pwd`" \
	--define "_specdir `pwd`" \
	@PACKAGE_NAME@.spec

EXTRA_DIST= \
	ChangeLog AUTHORS README NEWS \
	INSTALL COPYING gpl-2.0.txt lgpl-2.1.txt
