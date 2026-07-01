INJECTOR_OBJS = elf.o injector.o ptrace.o remote_call.o util.o shellcode.o proc.o
CFLAGS = -Wall -fPIC -I../../include

VERSION_MAJOR = 1
VERSION = 1.0.0

all: libinjector.so libinjector.a

libinjector.so.$(VERSION): $(INJECTOR_OBJS)
	$(CC) -shared -Wl,-soname,libinjector.so.$(VERSION_MAJOR) -o $@ $(INJECTOR_OBJS)

libinjector.so.$(VERSION_MAJOR): libinjector.so.$(VERSION)
	ln -sf libinjector.so.$(VERSION) $@

libinjector.so: libinjector.so.$(VERSION_MAJOR)
	ln -sf libinjector.so.$(VERSION_MAJOR) $@

libinjector.a: $(INJECTOR_OBJS)
	$(AR) rcs libinjector.a $(INJECTOR_OBJS)

install: all
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 libinjector.so.$(VERSION) $(DESTDIR)$(PREFIX)/lib/
	ln -sf libinjector.so.$(VERSION) $(DESTDIR)$(PREFIX)/lib/libinjector.so.$(VERSION_MAJOR)
	ln -sf libinjector.so.$(VERSION_MAJOR) $(DESTDIR)$(PREFIX)/lib/libinjector.so
	install -m 644 libinjector.a $(DESTDIR)$(PREFIX)/lib/

elf.o: elf.c injector_internal.h ../../include/injector.h
injector.o: injector.c injector_internal.h ../../include/injector.h
ptrace.o: ptrace.c injector_internal.h ../../include/injector.h
remote_call.o: remote_call.c injector_internal.h ../../include/injector.h
util.o: util.c injector_internal.h ../../include/injector.h
shellcode.o: shellcode.S
proc.o: proc.c proc.h ../../include/injector.h

clean:
	$(RM) libinjector.so libinjector.so.* libinjector.a $(INJECTOR_OBJS)

.PHONY: all install clean
