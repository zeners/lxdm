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

lxdmdir = $(datadir)/lxdm
lxdm_DATA = \
	data/lxdm.glade \
	data/lang.txt \
	$(NULL)

install-data-hook:
	chmod +x $(DESTDIR)/etc/lxdm/Xsession

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
	INSTALL COPYING
