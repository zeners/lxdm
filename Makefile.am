NULL =
SUBDIRS= \
	src \
	po \
	$(NULL)

lxdm_confdir = /etc/lxdm
lxdm_conf_DATA = \
	data/lxdm.conf \
	data/Xsession \
	$(NULL)

lxdmdir = $(datadir)/lxdm
lxdm_DATA = \
	data/lxdm.glade \
	data/lang.txt \
	$(NULL)

install-data-hook:
	chmod +x $(DESTDIR)/etc/lxdm/Xsession
