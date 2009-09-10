NULL =
SUBDIRS= \
	src \
	po \
	$(NULL)

lxdm_confdir = $(sysconfdir)/lxdm
lxdm_conf_DATA = \
	data/lxdm.conf \
	$(NULL)

lxdmdir = $(datadir)/lxdm
lxdm_DATA = \
	data/Xsession \
	data/lxdm.glade \
	$(NULL)

install-data-hook:
	chmod +x $(DESTDIR)$(lxdmdir)/Xsession
