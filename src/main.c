/*
 * main.c
 *
 * Copyright (C) 2009-2021 Nikias Bassen <nikias@gmx.li>
 * Copyright (C) 2013-2014 Martin Szulecki <m.szulecki@libimobiledevice.org>
 * Copyright (C) 2009 Hector Martin <hector@marcansoft.com>
 * Copyright (C) 2009 Paul Sladen <libiphone@paul.sladen.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <usbmuxd/config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#include <usbmuxd/log.h>
#include <usbmuxd/usb.h>
#include <usbmuxd/device.h>
#include <usbmuxd/client.h>
#include <usbmuxd/conf.h>
#include <pthread.h>

//static const char *socket_path = "/data/data/com.example.usbmuxd_testing/usbmuxd.sock";
//#define DEFAULT_LOCKFILE "/data/data/com.example.usbmuxd_testing/usbmuxd.pid"
//static const char *lockfile = DEFAULT_LOCKFILE;

char app_dir[200];
static char socket_path[200];
static char lockfile[200];

// задаем пути к сокету и lock-файлу
void set_paths(const char *_app_dir) {
    strcpy(app_dir, _app_dir);
    strcpy(socket_path, _app_dir);
    strcat(socket_path, "/usbmuxd.sock");

    strcpy(lockfile, _app_dir);
    strcat(lockfile, "/usbmuxd.lock");
}

// Global state used in other files
int should_exit;
int should_discover;
int use_logfile = 0;
int no_preflight = 0;

// Global state for main.c
static int verbose = 0;
static int foreground = 0;
static int drop_privileges = 0;
static const char *drop_user = NULL;
static int opt_disable_hotplug = 0;
static int opt_enable_exit = 0;
static int opt_exit = 0;
static int exit_signal = 0;
static int daemon_pipe;
static const char *listen_addr = NULL;

static int report_to_parent = 0;

static int create_socket(void)
{
	int listenfd;
	const char* socket_addr = socket_path;
	const char* tcp_port;
	char listen_addr_str[256];

	if (listen_addr) {
		socket_addr = listen_addr;
	}
	tcp_port = strrchr(socket_addr, ':');
	if (tcp_port) {
		tcp_port++;
		size_t nlen = tcp_port - socket_addr;
		char* hostname = malloc(nlen);
		struct addrinfo hints;
		struct addrinfo *result, *rp;
		int yes = 1;
		int res;

		strncpy(hostname, socket_addr, nlen-1);
		hostname[nlen-1] = '\0';

		memset(&hints, '\0', sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
		hints.ai_protocol = IPPROTO_TCP;

		res = getaddrinfo(hostname, tcp_port, &hints, &result);
		free(hostname);
		if (res != 0) {
			usbmuxd_log(LL_FATAL, "%s: getaddrinfo() failed: %s\n", __func__, gai_strerror(res));
			return -1;
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			listenfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (listenfd == -1) {
				listenfd = -1;
				continue;
			}

			if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(int)) == -1) {
				usbmuxd_log(LL_ERROR, "%s: setsockopt(): %s", __func__, strerror(errno));
				close(listenfd);
				listenfd = -1;
				continue;
			}

#ifdef SO_NOSIGPIPE
			if (setsockopt(listenfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
				usbmuxd_log(LL_ERROR, "%s: setsockopt(): %s", __func__, strerror(errno));
				close(listenfd);
				listenfd = -1;
				continue;
			}
#endif

#if defined(AF_INET6) && defined(IPV6_V6ONLY)
			if (rp->ai_family == AF_INET6) {
				if (setsockopt(listenfd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&yes, sizeof(int)) == -1) {
					usbmuxd_log(LL_ERROR, "%s: setsockopt() IPV6_V6ONLY: %s", __func__, strerror(errno));
				}
			}
#endif

			if (bind(listenfd, rp->ai_addr, rp->ai_addrlen) < 0) {
				usbmuxd_log(LL_FATAL, "%s: bind() failed: %s", __func__, strerror(errno));
				close(listenfd);
				listenfd = -1;
				continue;
			}

			const void *addrdata = NULL;
			if (rp->ai_family == AF_INET) {
				addrdata = &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
			}
#ifdef AF_INET6
			else if (rp->ai_family == AF_INET6) {
				addrdata = &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
			}
#endif
			if (addrdata) {
				char* endp = NULL;
				uint16_t listen_port = 0;
				if (rp->ai_family == AF_INET) {
					listen_port = ntohs(((struct sockaddr_in*)rp->ai_addr)->sin_port);
					if (inet_ntop(AF_INET, addrdata, listen_addr_str, sizeof(listen_addr_str)-6)) {
						endp = &listen_addr_str[0] + strlen(listen_addr_str);
					}
				}
#ifdef AF_INET6
				else if (rp->ai_family == AF_INET6) {
					listen_port = ntohs(((struct sockaddr_in6*)rp->ai_addr)->sin6_port);
					listen_addr_str[0] = '[';
					if (inet_ntop(AF_INET6, addrdata, listen_addr_str+1, sizeof(listen_addr_str)-8)) {
						endp = &listen_addr_str[0] + strlen(listen_addr_str);
					}
					if (endp) {
						*endp = ']';
						endp++;
					}
				}
#endif
				if (endp) {
					sprintf(endp, ":%u", listen_port);
				}
			}
			break;
		}
		freeaddrinfo(result);
		if (listenfd == -1) {
			usbmuxd_log(LL_FATAL, "%s: Failed to create listening socket", __func__);
			return -1;
		}
	} else {
		struct sockaddr_un bind_addr;

		if (strcmp(socket_addr, socket_path) != 0) {
			struct stat fst;
			if (stat(socket_addr, &fst) == 0) {
				if (!S_ISSOCK(fst.st_mode)) {
					usbmuxd_log(LL_FATAL, "FATAL: File '%s' already exists and is not a socket file. Refusing to continue.", socket_addr);
					return -1;
				}
			}
		}

		if (unlink(socket_addr) == -1 && errno != ENOENT) {
			usbmuxd_log(LL_FATAL, "%s: unlink(%s) failed: %s", __func__, socket_addr, strerror(errno));
			return -1;
		}

		listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (listenfd == -1) {
			usbmuxd_log(LL_FATAL, "socket() failed: %s", strerror(errno));
			return -1;
		}

		bzero(&bind_addr, sizeof(bind_addr));
		bind_addr.sun_family = AF_UNIX;
		strncpy(bind_addr.sun_path, socket_addr, sizeof(bind_addr.sun_path));
		bind_addr.sun_path[sizeof(bind_addr.sun_path) - 1] = '\0';

		if (bind(listenfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
			usbmuxd_log(LL_FATAL, "bind() failed: %s", strerror(errno));
			return -1;
		}
		chmod(socket_addr, 0666);

		snprintf(listen_addr_str, sizeof(listen_addr_str), "%s", socket_addr);
	}

	int flags = fcntl(listenfd, F_GETFL, 0);
	if (flags < 0) {
		usbmuxd_log(LL_FATAL, "ERROR: Could not get flags for socket");
	} else {
		if (fcntl(listenfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			usbmuxd_log(LL_FATAL, "ERROR: Could not set socket to non-blocking");
		}
	}

	// Start listening
	if (listen(listenfd, 256) != 0) {
		usbmuxd_log(LL_FATAL, "listen() failed: %s", strerror(errno));
		return -1;
	}

	usbmuxd_log(LL_INFO, "Listening on %s", listen_addr_str);

	return listenfd;
}

static void handle_signal(int sig)
{
	if (sig != SIGUSR1 && sig != SIGUSR2) {
		usbmuxd_log(LL_NOTICE,"Caught signal %d, exiting", sig);
		should_exit = 1;
	} else {
		if(opt_enable_exit) {
			if (sig == SIGUSR1) {
				usbmuxd_log(LL_INFO, "Caught SIGUSR1, checking if we can terminate (no more devices attached)...");
				if (device_get_count(1) > 0) {
					// we can't quit, there are still devices attached.
					usbmuxd_log(LL_NOTICE, "Refusing to terminate, there are still devices attached. Kill me with signal 15 (TERM) to force quit.");
				} else {
					// it's safe to quit
					should_exit = 1;
				}
			} else if (sig == SIGUSR2) {
				usbmuxd_log(LL_INFO, "Caught SIGUSR2, scheduling device discovery");
				should_discover = 1;
			}
		} else {
			usbmuxd_log(LL_INFO, "Caught SIGUSR1/2 but this instance was not started with \"--enable-exit\", ignoring.");
		}
	}
}

static void set_signal_handlers(void)
{
	struct sigaction sa;
	sigset_t set;

	// Mask all signals we handle. They will be unmasked by ppoll().
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigprocmask(SIG_SETMASK, &set, NULL);

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

#ifndef HAVE_PPOLL
static int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
	int ready;
	sigset_t origmask;
	int to = timeout->tv_sec*1000 + timeout->tv_nsec/1000000;

	sigprocmask(SIG_SETMASK, sigmask, &origmask);
	ready = poll(fds, nfds, to);
	sigprocmask(SIG_SETMASK, &origmask, NULL);

	return ready;
}
#endif

pthread_mutex_t exit_main_mutex;
int exit_now = 0;

static int main_loop(int listenfd)
{
	int to, cnt, i, dto;
	struct fdlist pollfds;
	struct timespec tspec;

	sigset_t empty_sigset;
	sigemptyset(&empty_sigset); // unmask all signals

	fdlist_create(&pollfds);
	while(!should_exit) {
		usbmuxd_log(LL_FLOOD, "main_loop iteration");
		to = usb_get_timeout();
		usbmuxd_log(LL_FLOOD, "USB timeout is %d ms", to);
		dto = device_get_timeout();
		usbmuxd_log(LL_FLOOD, "Device timeout is %d ms", dto);
		if(dto < to)
			to = dto;

		fdlist_reset(&pollfds);
		fdlist_add(&pollfds, FD_LISTEN, listenfd, POLLIN);
		usb_get_fds(&pollfds);
		client_get_fds(&pollfds);
		usbmuxd_log(LL_FLOOD, "fd count is %d", pollfds.count);

		tspec.tv_sec = to / 1000;
		tspec.tv_nsec = (to % 1000) * 1000000;
		cnt = ppoll(pollfds.fds, pollfds.count, &tspec, &empty_sigset);
		usbmuxd_log(LL_FLOOD, "poll() returned %d", cnt);
		if(cnt == -1) {
			if(errno == EINTR) {
				if(should_exit) {
					usbmuxd_log(LL_INFO, "Event processing interrupted");
					break;
				}
				if(should_discover) {
					should_discover = 0;
					usbmuxd_log(LL_INFO, "Device discovery triggered");
					usb_discover();
				}
			}
		} else if(cnt == 0) {
            pthread_mutex_lock(&exit_main_mutex);
            should_exit = exit_now;
            pthread_mutex_unlock(&exit_main_mutex);
            if (should_exit) {
                break;
            }
			if(usb_process() < 0) {
				usbmuxd_log(LL_FATAL, "usb_process() failed");
				fdlist_free(&pollfds);
				return -1;
			}
			device_check_timeouts();
		} else {
			int done_usb = 0;
			for(i=0; i<pollfds.count; i++) {
				if(pollfds.fds[i].revents) {
					if(!done_usb && pollfds.owners[i] == FD_USB) {
						if(usb_process() < 0) {
							usbmuxd_log(LL_FATAL, "usb_process() failed");
							fdlist_free(&pollfds);
							return -1;
						}
						done_usb = 1;
					}
					if(pollfds.owners[i] == FD_LISTEN) {
						if(client_accept(listenfd) < 0) {
							usbmuxd_log(LL_FATAL, "client_accept() failed");
							fdlist_free(&pollfds);
							return -1;
						}
					}
					if(pollfds.owners[i] == FD_CLIENT) {
						client_process(pollfds.fds[i].fd, pollfds.fds[i].revents);
					}
				}
			}
		}
	}
	fdlist_free(&pollfds);
	return 0;
}

int main_start(int argc, char *argv[], int fd);

void init_mutexes()
{
    // иницилизируем один раз при запуске приложения
    // уничтожать не будем, потому что непонятно где это делать, поэтому пусть живет весь процесс
	pthread_mutex_init(&exit_main_mutex, NULL);
}

// для остановки демона вызываем эту функцию только при отсоединении устройства
void set_daemon_stop_flag(int stop_flag) {
    pthread_mutex_lock(&exit_main_mutex);
	exit_now = stop_flag;
	pthread_mutex_unlock(&exit_main_mutex);
}

int mymain(int fd) {
    set_daemon_stop_flag(0);
    int result = main_start(1, NULL, fd);
    return result;
}

int main_start(int argc, char *argv[], int fd)
{
	int listenfd;
	int res = 0;
	int lfd;
	struct flock lock;
	char pids[10];

    no_preflight = 1;
    foreground = 1;

    verbose += LL_NOTICE;

	/* set log level to specified verbosity */
	log_level = verbose;

	usbmuxd_log(LL_NOTICE, "usbmuxd v%s starting up", PACKAGE_VERSION);
	should_exit = 0;
	should_discover = 0;

	set_signal_handlers();
	signal(SIGPIPE, SIG_IGN);

	if (lockfile) {
		res = lfd = open(lockfile, O_WRONLY|O_CREAT, 0644);
		if(res == -1) {
			usbmuxd_log(LL_FATAL, "Could not open lockfile %s", lockfile);
			goto terminate;
		}
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		lock.l_pid = 0;
		fcntl(lfd, F_GETLK, &lock);
		close(lfd);
	}

	if (lockfile) {
		unlink(lockfile);
	}

	if (lockfile) {
		// now open the lockfile and place the lock
		res = lfd = open(lockfile, O_WRONLY|O_CREAT|O_TRUNC|O_EXCL, 0644);
		if(res < 0) {
			usbmuxd_log(LL_FATAL, "Could not open pidfile '%s'", lockfile);
			goto terminate;
		}
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_start = 0;
		lock.l_len = 0;
		if ((res = fcntl(lfd, F_SETLK, &lock)) < 0) {
			usbmuxd_log(LL_FATAL, "Locking pidfile '%s' failed!", lockfile);
			goto terminate;
		}
		sprintf(pids, "%d", getpid());
		if ((size_t)(res = write(lfd, pids, strlen(pids))) != strlen(pids)) {
			usbmuxd_log(LL_FATAL, "Could not write pidfile!");
			if(res >= 0)
				res = -2;
			goto terminate;
		}
	}

	// set number of file descriptors to higher value
	struct rlimit rlim;
	getrlimit(RLIMIT_NOFILE, &rlim);
	rlim.rlim_max = 65536;
	setrlimit(RLIMIT_NOFILE, (const struct rlimit*)&rlim);

	usbmuxd_log(LL_INFO, "Creating socket");
	res = listenfd = create_socket();
	if(listenfd < 0)
		goto terminate;

	client_init();
	device_init();
	usbmuxd_log(LL_INFO, "Initializing USB");
	if((res = usb_init(fd)) < 0)
		goto terminate;



	usbmuxd_log(LL_INFO, "%d device%s detected", res, (res==1)?"":"s");

	usbmuxd_log(LL_NOTICE, "Initialization complete");

	res = main_loop(listenfd);
	if(res < 0)
		usbmuxd_log(LL_FATAL, "main_loop failed");

	usbmuxd_log(LL_NOTICE, "usbmuxd shutting down");
	device_kill_connections();
	usb_shutdown();
	device_shutdown();
	client_shutdown();
	usbmuxd_log(LL_NOTICE, "Shutdown complete");

terminate:

	if (res < 0)
		res = -res;
	else
		res = 0;

	return res;
}
