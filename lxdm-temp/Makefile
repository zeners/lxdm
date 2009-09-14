NAME=lxdm
VERSION=0.0.3
PREFIX=/usr
CFLAGS=-Wall -g `pkg-config --cflags gdk-2.0`
LDFLAGS=
LIBS=`pkg-config --libs gdk-2.0` -lcrypt -lXmu -lpam
OBJS=lxdm.o ui.o

all: lxdm lxdm-greeter

lxdm: $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

lxdm-greeter: greeter.c
	$(CC) -Wall -g `pkg-config --cflags gtk+-2.0` -o $@ $^ `pkg-config --libs gtk+-2.0`

clean:
	@rm -rf lxdm lxdm-greeter $(OBJS)

install: lxdm lxdm-greeter
	install -m 700 lxdm $(DESTDIR)$(PREFIX)/bin/lxdm
	test -e $(DESTDIR)/etc/lxdm || mkdir $(DESTDIR)/etc/lxdm
	install -m 755 Xsession $(DESTDIR)/etc/lxdm/Xsession
	install -m 755 lxdm-greeter $(DESTDIR)/usr/libexec/lxdm-greeter
	test -e $(DESTDIR)/etc/lxdm/lxdm.conf || install -m 755 lxdm.conf $(DESTDIR)/etc/lxdm/lxdm.conf

uninstall:
	@rm -rf $(PREFIX)/bin/lxdm
	@rm -rf $(PREFIX)/etc/lxdm.conf

dist:
	@rm -rf $(NAME)-$(VERSION)
	@mkdir $(NAME)-$(VERSION)
	@cp -r *.c *.h ui.c Makefile lxdm.conf Xsession $(NAME)-$(VERSION)
	@tar cvzf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	@rm -rf $(NAME)-$(VERSION)
