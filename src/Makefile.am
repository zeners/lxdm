NULL =

bin_PROGRAMS = lxdm

lxdm_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	$(NULL)

lxdm_LDFLAGS = \
	$(GTK_LIBS) \
	$(NULL)

lxdm_SOURCES = \
	lxdm.c lxdm.h \
	ui.c ui.h \
	$(NULL)
