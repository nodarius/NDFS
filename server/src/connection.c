#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "fs.h"
#include "connection.h"


static int get_active_fd(struct epoll_event *ev)
{
	struct e_con *econ = ev->data.ptr;
	if (econ->type == LISTENING) {
		return econ->lcon.sockfd;
	} else if (econ->type == CLIENT) {
		return econ->con.sockfd;
	} else {
		sentinel("Unknown econ type.");
	}
	return 0;
}

static void modify_epoll_events(int epfd, struct epoll_event *old, uint32_t new_events)
{
        struct epoll_event ev;
        ev.data.ptr = old->data.ptr;
        ev.events = new_events;
	
        int fd = get_active_fd(old);
        int st = epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
        if (st == -1) {
                log_debug("error epoll ctl");
        }
}


static char *get_peer_ip(int sockfd)
{
        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        getpeername(sockfd, (struct sockaddr*) &addr, &len);
        struct sockaddr_in *sin = (struct sockaddr_in*) &addr;
        char *ip = inet_ntoa(sin->sin_addr);
        return ip;
}


int accept_new_connection(struct global *glob, struct epoll_event *ev)
{
	log_function();
	check_kill(glob && ev, "Null parameter");

	struct e_con *econ = ev->data.ptr;
	printf("econ type is: %d\n", econ->type);
	check_kill(econ->type == LISTENING, "Error in logic.");
	struct listening_con *lcon = &econ->lcon;

	printf("sockfd is: %d\n", lcon->sockfd);
	int sockfd = accept(lcon->sockfd, NULL, NULL);
	if (sockfd == -1) {
		log_warning("Could not accept.");
		sentinel("");
		return 0;
	}

	struct e_con *new_econ = calloc(1, sizeof *econ);
	check_mem(new_econ);
	new_econ->type = CLIENT;
	new_econ->con.sockfd = sockfd;
	new_econ->con.ip = get_peer_ip(sockfd);

	struct epoll_event new_event;
	new_event.data.ptr = new_econ;
	new_event.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;

	if (epoll_ctl(glob->epfd, EPOLL_CTL_ADD, sockfd, &new_event) == -1)  {
		sentinel("epoll ctl add.");
	}
	log_info("accepted new connection.");

	return 1;
}


int connection_read(struct global *glob, struct epoll_event *ev)
{
	log_function();
	struct e_con *econ = ev->data.ptr;
	check_kill(econ->type == CLIENT, "Error in logic");
	struct client_con *con = &econ->con;

	int n = fs_recv(con);
//	int n = recv_to_buffer(con);
	if (n <= 0) {
		/* remove read & write */
		uint32_t new_events = EPOLLHUP | EPOLLRDHUP | EPOLLERR;
		modify_epoll_events(glob->epfd, ev, new_events);
		connection_clear(glob, ev);
		return 0;
	}
	uint32_t new_events = EPOLLIN | EPOLLOUT | EPOLLHUP |
		EPOLLRDHUP | EPOLLERR;
	modify_epoll_events(glob->epfd, ev, new_events);
		 
	return n;
}

int connection_write(struct global *glob, struct epoll_event *ev)
{
	log_function();
	struct e_con *econ = ev->data.ptr;
	check_kill(econ->type == CLIENT, "Error in logic.");
	struct client_con *con = &econ->con;
	int n = fs_send(con);
//	int n = send_from_buffer(con);
	if (n < 0) {
		uint32_t new_events = EPOLLHUP | EPOLLRDHUP | EPOLLERR;
                modify_epoll_events(glob->epfd, ev, new_events);
	} else {
                uint32_t new_events = EPOLLIN | EPOLLOUT |
                        EPOLLHUP | EPOLLRDHUP | EPOLLERR;
		if (con->sendbuf.len_l == 0) {
			new_events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;
		}
                modify_epoll_events(glob->epfd, ev, new_events);
	}
	
	return n;
}

int connection_clear(struct global *glob, struct epoll_event *ev)
{
	log_function();
	int sockfd = get_active_fd(ev);
	close(sockfd);
	/* TODO free */
	return 1;
}
