#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include "src/logger.h"
#include "src/types.h"
#include "src/connection.h"

#define MAX_EVENTS 1000

void start_logging()
{
	setlogmask(LOG_UPTO (LOG_WARNING));
	openlog("server", LOG_CONS | LOG_PID | LOG_NDELAY |
		LOG_PERROR, LOG_LOCAL1);
	log_info("server started."); /* useful when grepping log */
}

int create_listening_socket(const char *port)
{
        const char *ip = "0.0.0.0";
        struct addrinfo *hints = calloc(1, sizeof(struct addrinfo));
        struct addrinfo *info = calloc(1, sizeof(struct addrinfo));
        hints->ai_socktype = SOCK_STREAM;
        hints->ai_family = AF_UNSPEC;
        if (getaddrinfo(ip, port, hints, &info) != 0) {
                goto err_listening_port;
        }
        int sockfd = socket(info->ai_family, info->ai_socktype,
                            info->ai_protocol);
        fcntl(sockfd, F_SETFL, O_NONBLOCK);

        int optval = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
        if (sockfd == -1) {
                goto err_listening_port;
        }
        if (bind(sockfd, info->ai_addr, info->ai_addrlen) == -1) {
                goto err_listening_port;
        }
        if (listen(sockfd, 20000) == -1) {
                goto err_listening_port;
        }
        freeaddrinfo(info);
        return sockfd;

err_listening_port:
        freeaddrinfo(info);
        log_warning("Unable to listen on port: %s\n", port);
        return -1;
}


static int start_listening(int epfd, char *port)
{
	log_function();
	check_kill(epfd > 0 && port, "Invalid arguments");

	struct epoll_event ev;
	int sockfd = create_listening_socket(port);
	if (sockfd <= 0) {
		return 0;
	}
	ev.events = EPOLLIN;
	struct e_con *econ = calloc(1, sizeof *econ);
	econ->type = LISTENING;
	econ->lcon.sockfd = sockfd;
	ev.data.ptr = econ;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
		log_error("epoll ctl add. port: %s", port);
	}
	return 1;
}

void open_epfd(struct global *glob)
{
	log_function();
	check_kill(glob, "Null parameter");

	int epfd = epoll_create1(0);
	check_kill(epfd != -1, "Could not create epoll file descriptor");
	glob->epfd = epfd;
}

void process_events(struct global *glob, struct epoll_event *evlist,
		    int n_events)
{
	log_function();
	int i;
	for (i = 0; i < n_events; i++) {
		struct epoll_event *ev = &evlist[i];
		struct e_con *econ = ev->data.ptr;
		if (ev->events & EPOLLIN) {
			if (econ->type == LISTENING) {
				accept_new_connection(glob, ev);
			} else if (econ->type == CLIENT) {
				connection_read(glob, ev);
			} else {
				sentinel("Unknown econ type: %d", econ->type);
			}
			continue;
		}
		if (ev->events & EPOLLOUT
		    && !(ev->events & EPOLLRDHUP)
		    && !(ev->events & EPOLLERR)
		    && !(ev->events & EPOLLHUP)) {
			if (econ->type == CLIENT) {
				connection_write(glob, ev);
			} else {
				sentinel("Why would this happen? %d",
					 econ->type);
			}
			continue;
		}
                if (ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)
				  && !(ev->events & EPOLLIN)) {
			connection_clear(glob, ev);
                }
		
	}
}

void run_loop(struct global *glob)
{
	log_function();

	struct epoll_event evlist[MAX_EVENTS];
	while (1) {
		int ready = epoll_wait(glob->epfd, evlist, MAX_EVENTS, -1);
		if (ready == -1) {
			if (errno == EINTR) {
				log_warning("Epoll_wait interrupted");
				continue;
			} else {
				sentinel("epoll_wait");
			}
		}
		log_info("%d ready file descriptors", ready);
		process_events(glob, evlist, ready);
	}
}

/* IMPORTANT */
void do_nothing(){}

int main(int argc, char **argv)
{
	if (argc < 3) {
		printf("Usage: %s root_directory_path port_number\n", argv[0]);
		return 0;
	}
	start_logging();
	signal(SIGPIPE, do_nothing);
	struct global glob;
	memset(&glob, 0, sizeof glob);
	open_epfd(&glob);
	if (chdir(argv[1]) < 0) {
		sentinel("Could not chdir.");
	}
	if (chroot(".") < 0) {
		sentinel("Could not chroot.");
	}

	if (!start_listening(glob.epfd, argv[2])) {
		return -1;
	}

	run_loop(&glob);

	return 0;
}
