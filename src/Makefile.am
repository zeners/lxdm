NULL =

bin_PROGRAMS = lxdm lxdm-greeter-gtk

lxdm_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	-DLXDM_DATA_DIR=\"$(datadir)/lxdm\" \
	$(NULL)

lxdm_LDFLAGS = \
	$(GTK_LIBS) \
	$(NULL)

lxdm_SOURCES = \
	lxdm.c lxdm.h \
	ui.c \
	$(NULL)

lxdm_greeter_gtk_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	-DLXDM_DATA_DIR=\"$(datadir)/lxdm\" \
	$(NULL)

lxdm_greeter_gtk_LDFLAGS = \
	$(GTK_LIBS) \
	$(NULL)

lxdm_greeter_gtk_SOURCES = \
	greeter.c \
	lang.c lang.h \
	$(NULL)

