
flashpolicyserv:
	cc -Wall -g -levent -o flashpolicyserv flashpolicyserv.c

all: flashpolicyserv

install: flashpolicyserv
	install -D -m 755 flashpolicyserv $(DESTDIR)/usr/sbin/flashpolicyserv
	install -D -m 644 flashpolicyserv.8 $(DESTDIR)/usr/share/man/man8/flashpolicyserv.8

clean:
	rm -f flashpolicyserv

