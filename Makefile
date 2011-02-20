
flashpolicyserv:
	cc -Wall -g -levent -o flashpolicyserv flashpolicyserv.c

all: flashpolicyserv

install: flashpolicyserv
	install -m 755 flashpolicyserv /usr/sbin/flashpolicyserv
	install -m 644 flashpolicyserv.8 /usr/share/man/man8/

clean:
	rm -f flashpolicyserv

