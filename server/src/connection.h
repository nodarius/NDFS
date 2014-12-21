#ifndef CONNECTION_H
#define CONNECTION_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include "logger.h"
#include "types.h"
#include "vector.h"

struct buffer {
	void *data;
	int len_a;
	int len_l;
};

struct client_con {
	int sockfd;
	struct buffer recbuf;
	struct buffer sendbuf;
	char *ip;
	vec_t open_files;
};

struct listening_con {
	int sockfd;
};

enum CON_TYPE {
	LISTENING,
	CLIENT
};

struct e_con {
	enum CON_TYPE type;
	union {
		struct listening_con lcon;
		struct client_con con;
	};
};

int accept_new_connection(struct global *glob, struct epoll_event *ev);
int connection_read(struct global *glob, struct epoll_event *ev);
int connection_write(struct global *glob, struct epoll_event *ev);
int connection_clear(struct global *glob, struct epoll_event *ev);

#endif
