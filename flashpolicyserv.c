/* Simple flash socket policy server.
 * Licensed under the MIT license:
 * http://www.opensource.org/licenses/mit-license.php
 */
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DFLT_PORT 843
#define DFLT_FILE "/etc/flash_policy.xml"
#define DFLT_USER "nobody"
#define DFLT_CHROOT "/var/run"
#define PIDFILE "/var/run/flashpolicyserv.pid"

extern char *__progname;
static char *policy;

typedef struct client_t {
	int fd;
	int sent;
	struct bufferevent *buf_ev;
} client_t;

void setnonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(fd, F_SETFL, flags);
}

void write_cb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *evreturn;
	struct client_t *client = (struct client_t *)arg;

	if (client->sent) {
		bufferevent_free(client->buf_ev);
		close(client->fd);
		free(client);
		return;
	}

	evreturn = evbuffer_new();
	/* include a terminal null byte, per flash's requirements */
	evbuffer_add(evreturn, policy, strlen(policy) + 1);
	bufferevent_write_buffer(bev, evreturn);
	bufferevent_settimeout(bev, 5, 5);
	evbuffer_free(evreturn);
	client->sent = 1;
}

void read_cb(struct bufferevent *incoming, void *arg)
{
}

void error_cb(struct bufferevent *bev, short what, void *arg)
{
	struct client_t *client = (struct client_t *)arg;
	bufferevent_free(client->buf_ev);
	close(client->fd);
	free(client);
}

void accept_cb(int fd, short ev, void *arg)
{
	int client_fd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	struct client_t *client;

	client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
	if (client_fd < 0) {
		syslog(LOG_ERR, "accept() failed: %s", strerror(errno));
		return;
	}
	syslog(LOG_INFO, "%s connected", inet_ntoa(client_addr.sin_addr));

	setnonblock(client_fd);

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		syslog(LOG_ERR, "malloc failed");
		exit(1);
	}
	client->sent = 0;
	client->fd = client_fd;

	client->buf_ev = bufferevent_new(client_fd, read_cb, write_cb,
			error_cb, client);

	bufferevent_enable(client->buf_ev, EV_WRITE);
}

void loadpolicy(char *file)
{
	struct stat st;
	int fd;

	if ((stat(file, &st)) < 0) {
		syslog(LOG_ERR, "stat(%s) failed: %s", file, strerror(errno));
		exit(1);
	}

	/* plus one byte for null byte ending */
	if ((policy = calloc(1, st.st_size + 1)) == NULL) {
		syslog(LOG_ERR, "malloc failed");
		exit(1);
	}

	if ((fd = open(file, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "open(%s) failed: %s", file, strerror(errno));
		exit(1);
	}

	read(fd, policy, st.st_size);
	close(fd);
}

int getsock(int port)
{
	struct sockaddr_in saddr;
	int sock;
	int reuse = 1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR, "socket failed: %s", strerror(errno));
		exit(1);
	}

	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		syslog(LOG_ERR, "bind failed: %s", strerror(errno));
		exit(1);
	}

	if (listen(sock, 5) < 0) {
		syslog(LOG_ERR, "listen failed: %s", strerror(errno));
		exit(1);
	}

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	setnonblock(sock);

	return sock;
}

void usage(void)
{
	fprintf(stderr,
		"%s [-f policyfile] [-p port] [-u username] [-c chrootdir]\n"
		"Defaults: -f %s, -p %i, -u %s, -c %s\n",
		__progname, DFLT_FILE, DFLT_PORT, DFLT_USER, DFLT_CHROOT);

}

void daemonize(char *dir, char *user)
{
        pid_t pid;
	FILE *pidfd;
        struct passwd *pw;

        if ((pidfd = fopen(PIDFILE, "w")) == NULL) {
                fprintf(stderr, "Failed to open pid file %s: %s\n",
                                PIDFILE, strerror(errno));
        }

        if ((pw = getpwnam(user)) == NULL) {
                fprintf(stderr, "getpwnam(%s) failed: %s\n",
                                user, strerror(errno));
                exit(EXIT_FAILURE);
        }
                        ;;
        if ((pid = fork()) < 0) {
                fprintf(stderr, "fork failed: %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (pid > 0)
                _exit(0);
        if (setsid() < 0) {
                syslog(LOG_ERR, "setsid() failed: %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
        if ((pid = fork()) < 0) {
                syslog(LOG_ERR, "fork (2) failed: %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (pid > 0) {
        	if (pidfd != NULL) {
                	fprintf(pidfd, "%d\n", pid);
                	fclose(pidfd);
		}
                _exit(0);
	}
        if (!freopen("/dev/null", "r", stdin)  ||
            !freopen("/dev/null", "w", stdout) ||
            !freopen("/dev/null", "w", stderr)) {
                syslog(LOG_WARNING, "close std fds %s failed: %s\n",
                                dir, strerror(errno));
        }
        if (chroot(dir) < 0) {
                syslog(LOG_ERR, "chroot(%s) failed: %s\n",
                                dir, strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (chdir("/") < 0) {
                syslog(LOG_ERR, "chdir(\"/\") failed: %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (setgroups(1, &pw->pw_gid) < 0) {
                syslog(LOG_ERR, "setgroups() failed: %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (setgid(pw->pw_gid)) {
                syslog(LOG_ERR, "setgid %i (user=%s) failed: %s\n",
                                pw->pw_gid, user, strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (setuid(pw->pw_uid)) {
                syslog(LOG_ERR, "setuid %i (user=%s) failed: %s\n",
                                pw->pw_uid, user, strerror(errno));
                exit(EXIT_FAILURE);
        }
}

void loop_event(int sock)
{
	struct event accept_event;

	event_init();
	event_set(&accept_event, sock, EV_READ | EV_PERSIST, accept_cb, NULL);
	event_add(&accept_event, NULL);
	event_dispatch();
}

int main(int argc, char **argv)
{
	int sock, c;

	char *file = DFLT_FILE;
	char *username = DFLT_USER;
	char *chrootdir = DFLT_CHROOT;
	int port = DFLT_PORT;

	opterr = 0;
	while ((c = getopt (argc, argv, "f:p:u:c:")) != -1) {
		switch (c) {
			case 'f':
				file = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'u':
				username = optarg;
				break;
			case 'c':
				chrootdir = optarg;
				break;
			default:
				usage();
				exit(EXIT_FAILURE);
		}
	}

        openlog(__progname, LOG_PID | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "starting");

	loadpolicy(file);
	sock = getsock(port);
	daemonize(chrootdir, username);

	loop_event(sock);

	syslog(LOG_INFO, "exiting");
	close(sock);
	closelog();

	exit(EXIT_SUCCESS);
}

