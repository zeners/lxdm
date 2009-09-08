NAME=lxdm
VERSION=0.0.2
PREFIX=/usr
CFLAGS=-Wall -g `pkg-config --cflags gtk+-2.0`
LDFLAGS=
LIBS=`pkg-config --libs gtk+-2.0` -lcrypt -lXmu -lpam
OBJS=lxdm.o ui.o

all: lxdm

lxdm: $(OBJS)
	$(CC) -o $@ $^ $(LIBS)

clean:
	@rm -rf lxdm $(OBJS)

install: lxdm
	install -m 700 lxdm $(DESTDIR)$(PREFIX)/bin/lxdm
	test -e $(DESTDIR)/etc/lxdm || mkdir $(DESTDIR)/etc/lxdm
	install -m 755 Xsession $(DESTDIR)/etc/lxdm/Xsession
	test -e $(DESTDIR)/etc/lxdm/lxdm.conf || install -m 300 lxdm.conf $(DESTDIR)/etc/lxdm/lxdm.conf

uninstall:
	@rm -rf $(PREFIX)/bin/lxdm
	@rm -rf $(PREFIX)/etc/lxdm.conf

dist:
	@rm -rf $(NAME)-$(VERSION)
	@mkdir $(NAME)-$(VERSION)
	@cp -r lxdm.c lxdm.h ui.c Makefile lxdm.conf Xsession $(NAME)-$(VERSION)
	@tar cvzf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	@rm -rf $(NAME)-$(VERSION)
