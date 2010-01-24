NULL =

sbin_PROGRAMS = lxdm-binary

lxdm_binary_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	-DLXDM_DATA_DIR=\"$(datadir)/lxdm\" \
	$(CONSOLEKIT_CFLAGS) \
	-Werror-implicit-function-declaration \
	-Wall \
	$(NULL)

lxdm_binary_LDADD = \
	$(GTK_LIBS) \
	$(CONSOLEKIT_LIBS) \
	$(NULL)

lxdm_binary_SOURCES = \
	lxdm.c lxdm.h \
	ui.c \
	$(NULL)

libexec_PROGRAMS = lxdm-greeter-gtk

lxdm_greeter_gtk_CFLAGS = \
	$(GTK_CFLAGS) \
	-DCONFIG_DIR=\"$(sysconfdir)/lxdm\" \
	-DLXDM_DATA_DIR=\"$(datadir)/lxdm\" \
	-DPACKAGE_LOCALE_DIR=\"$(datadir)/locale\" \
	-DGNOMELOCALEDIR=PACKAGE_LOCALE_DIR \
	-DLIBLOCALEDIR=\""$(prefix)/lib/locale"\" \
	-Werror-implicit-function-declaration
	$(NULL)

lxdm_greeter_gtk_LDADD = \
	$(GTK_LIBS) \
	$(NULL)

lxdm_greeter_gtk_SOURCES = \
	greeter.c \
	lang.c lang.h \
	gdm/gdm-languages.c gdm/gdm-languages.h \
	gdm/locarchive.h \
	$(NULL)

