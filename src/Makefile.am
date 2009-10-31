NULL =

bin_PROGRAMS = lxdm-binary lxdm-greeter-gtk

lxdm_binary_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	-DLXDM_DATA_DIR=\"$(datadir)/lxdm\" \
	$(CONSOLEKIT_CFLAGS) \
	$(NULL)

lxdm_binary_LDADD = \
	$(GTK_LIBS) \
	$(CONSOLEKIT_LIBS) \
	$(NULL)

lxdm_binary_SOURCES = \
	lxdm.c lxdm.h \
	ui.c \
	$(NULL)

lxdm_greeter_gtk_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	-DLXDM_DATA_DIR=\"$(datadir)/lxdm\" \
	$(NULL)

lxdm_greeter_gtk_LDADD = \
	$(GTK_LIBS) \
	$(NULL)

lxdm_greeter_gtk_SOURCES = \
	greeter.c \
	lang.c lang.h \
	$(NULL)

