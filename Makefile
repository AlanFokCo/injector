SRC_DIR = src/linux

PREFIX ?= /usr/local

all:
	cd $(SRC_DIR) && $(MAKE)
	cd cmd && $(MAKE)

install: all
	cd $(SRC_DIR) && $(MAKE) install PREFIX=$(PREFIX)
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 include/injector.h $(DESTDIR)$(PREFIX)/include/
	install -d $(DESTDIR)$(PREFIX)/lib/pkgconfig
	sed -e 's,@PREFIX@,$(PREFIX),' libinjector.pc.in > $(DESTDIR)$(PREFIX)/lib/pkgconfig/libinjector.pc

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/include/injector.h
	rm -f $(DESTDIR)$(PREFIX)/lib/libinjector.so
	rm -f $(DESTDIR)$(PREFIX)/lib/libinjector.so.1
	rm -f $(DESTDIR)$(PREFIX)/lib/libinjector.so.1.0.0
	rm -f $(DESTDIR)$(PREFIX)/lib/libinjector.a
	rm -f $(DESTDIR)$(PREFIX)/lib/pkgconfig/libinjector.pc

check:
	cd tests && $(MAKE) check

unit:
	cd tests && $(MAKE) unit

clean:
	cd $(SRC_DIR) && $(MAKE) clean
	cd cmd && $(MAKE) clean
	cd tests && $(MAKE) clean

.PHONY: all install uninstall check unit clean
