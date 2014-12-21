#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "constants.h"
#include "syscalls.h"
#include "common.h"

static void print_d(void *ptr, int len)
{
	return;
        printf("printing:\n");
        int i;
        for (i = 0; i < len; i++) {
                printf("%d ", ((char*) ptr)[i]);
        }
        printf("\n");
}

static void print_ch(void *ptr, int len)
{
	return;
        printf("printing:\n");
        int i;
        for (i = 0; i < len; i++) {
                printf("%c", ((char*) ptr)[i]);
        }
        printf("\n");
}


struct global *get_glob()
{
	struct fuse_context *fuse = fuse_get_context();
	struct global *glob = fuse->private_data;
	check_kill(glob, "fb_init not called?");
	return glob;
}

static int send_to_sock(int sockfd, void *buf, int buflen)
{
	char *ptr = buf;
	while(buflen > 0) {
		int n = send(sockfd, ptr, buflen, 0);
		if (n < 1) {
			sentinel("could not send.\n"); /* TODO */
			return 0;
		}
		ptr += n;
		buflen -= n;
	}
	return 1;
}

static void *recv_from_sock(int sockfd, int *size)
{
	uint32_t len;
	int n  = recv(sockfd, &len, sizeof(len), 0);
	if (n != sizeof(len)) {
		*size = 0;
		return NULL;
		sentinel("n was: %d\n", n); /* TODO */
	}
	int len_h = ntohl(len);
	char *buf = calloc(1, len_h);
	char *res = buf;
	*size = len_h;
	while (len_h > 0) {
		n = recv(sockfd, buf, len_h, 0);
		if (n < 1) {
			sentinel("could not recv."); /* TODO */
			*size = 0;
			return NULL;
		}
		buf += n;
		len_h -= n;
	}
	return res;
}

/******************************************************************************/

void *ndfs_init(struct fuse_conn_info *conn)
{
	log_function();

	if (errno == EPERM)
		errno = 0;

	struct global *glob = calloc(1, sizeof *glob);
	check_mem(glob);

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	check_kill(sockfd != -1, "Could not create socket");
	struct addrinfo hints, *res;
	bzero(&hints, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	int status = getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &res);
	status = connect(sockfd, res->ai_addr, res->ai_addrlen);
	check_kill(status != -1, "Could not connect.");
	glob->sockfd = sockfd;
	freeaddrinfo(res);

	return glob;
}

void ndfs_destroy(void *private_data)
{
	log_function();
	/* TODO */
}

int ndfs_getattr(const char *path, struct stat *stbuf)
{
	log_function("path: %s", path);

	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(GETATTR);
	uint32_t len = sizeof(pathlen) + pathlen + sizeof(commandlen)
		+ commandlen;
	char buf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t len_n = htonl(len);
	memcpy(buf, &len_n, sizeof(len_n));
	memcpy(buf + sizeof(len_n), &commandlen_n, sizeof(commandlen));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen), GETATTR, commandlen);
	memcpy(buf + sizeof(len_n) + sizeof(commandlen) + commandlen, &pathlen_n,
	       sizeof(pathlen));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen)
	       + commandlen + sizeof(pathlen), path, pathlen);

	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, buf, len + sizeof(len));

	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	if (resp_len == 0) {
		free(resp);
		log_warning(" no such file.: %s\n", path);
		return -ENOENT;
	}

	uint32_t size = *(uint32_t*) resp;
	uint32_t mode = ((uint32_t*) resp)[1];
	uint32_t size_h = ntohl(size);
	uint32_t mode_h = ntohl(mode);
	stbuf->st_mode = mode_h;
	stbuf->st_size = size_h;
	stbuf->st_nlink = 1;
	free(resp);
	return 0;
}

int ndfs_mkdir(const char *path, mode_t mode)
{
	log_function("Path is: %s", path);

	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(MKDIR);
	uint32_t len = sizeof(pathlen) + pathlen + sizeof(commandlen)
		+ commandlen;
	char buf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t len_n = htonl(len);
	memcpy(buf, &len_n, sizeof(len_n));
	memcpy(buf + sizeof(len_n), &commandlen_n, sizeof(commandlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n), MKDIR, commandlen);
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen,
	       &pathlen_n, sizeof(pathlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen
	       + sizeof(pathlen_n), path, pathlen);
	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, buf, len + sizeof(len));
	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	if (resp_len == 0) {
		free(resp);
		log_warning("could not mkdir\n");
		return -ENOENT;
	}
	free(resp);
	return 0;
}

int ndfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		      off_t offset, struct fuse_file_info *fi)
{
	log_function("path is: %s", path);
	
	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(READDIR);
	uint32_t len = sizeof(pathlen) + pathlen + sizeof(commandlen)
	        + commandlen;
	char sendbuf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t len_n = htonl(len);

	memcpy(sendbuf, &len_n, sizeof(len_n));
	memcpy(sendbuf + sizeof(len_n), &commandlen_n, sizeof(commandlen_n));
	memcpy(sendbuf + sizeof(len_n) + sizeof(commandlen),
	       READDIR, commandlen);	
	memcpy(sendbuf + sizeof(len_n) + sizeof(commandlen_n) + commandlen,
	       &pathlen_n, sizeof(pathlen_n));
	memcpy(sendbuf + sizeof(len_n) + sizeof(commandlen_n) + commandlen
	       + sizeof(pathlen_n), path, pathlen);

	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, sendbuf, len + sizeof(len));

	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	if (resp_len == 0) {
		free(resp);
		log_warning("could not readdir.\n");
		return -ENOENT;
	}

	char *ptr = resp;
	while (resp_len > 0) {
		uint32_t len = *(uint32_t*) ptr;
		len = ntohl(len);
		char filename[len + 1];
		filename[len] = 0;
		memcpy(filename, ptr + sizeof(len), len);
		ptr += sizeof(len) + len;
		resp_len -= sizeof(len);
		resp_len -= len;
		filler(buf, filename, NULL, 0);
	}

	free(resp);	
	return 0;
}


int ndfs_rename(const char *oldpath, const char *newpath)
{
	log_function("Oldpath: %s, Newpath: %s", oldpath, newpath);
	uint32_t oldlen = strlen(oldpath);
	uint32_t newlen = strlen(newpath);
	uint32_t commandlen = strlen(RENAME);
	uint32_t len = sizeof(oldlen) + oldlen + sizeof(newlen) +
		newlen + sizeof(commandlen) + commandlen;
	char sendbuf[len + sizeof(len)];
	uint32_t oldlen_n = htonl(oldlen);
	uint32_t newlen_n = htonl(newlen);
	uint32_t len_n = htonl(len);
	uint32_t commandlen_n = htonl(commandlen);

	char *ptr = sendbuf;
	memcpy(ptr, &len_n, sizeof(len_n));
	ptr += sizeof(len_n);
	memcpy(ptr, &commandlen_n, sizeof(commandlen_n));
	ptr += sizeof(commandlen_n);
	memcpy(ptr, RENAME, commandlen);
	ptr += commandlen;
	memcpy(ptr, &oldlen_n, sizeof(oldlen_n));
	ptr += sizeof(oldlen_n);
	memcpy(ptr, oldpath, oldlen);
	ptr += oldlen;
	memcpy(ptr, &newlen_n, sizeof(newlen_n));
	ptr += sizeof(newlen_n);
	memcpy(ptr, newpath, newlen);
	ptr += newlen;
	print_ch(sendbuf, len + sizeof(len));
	print_d(sendbuf, len + sizeof(len));
	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, sendbuf, len + sizeof(len));

	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	uint32_t err = *(uint32_t*) resp;
	return -err;
}

int ndfs_utime(const char *path, struct utimbuf *ubuf)
{
	return 0;
}

int ndfs_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
	log_function("Path is: %s", path);
	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(CREATE);
	uint32_t len = sizeof(pathlen) + pathlen + sizeof(commandlen)
		+ commandlen;
	char buf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t len_n = htonl(len);

	memcpy(buf, &len_n, sizeof(len_n));
	memcpy(buf + sizeof(len_n), &commandlen_n, sizeof(commandlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n), CREATE, commandlen);
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen,
	       &pathlen_n, sizeof(pathlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen
	       + sizeof(pathlen_n), path, pathlen);
	
	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, buf, len + sizeof(len));
	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	uint32_t err = *(uint32_t*) resp;
	uint32_t fd = *(uint32_t*) ((char*) resp + sizeof(uint32_t));
	err = ntohl(err);
	fd = ntohl(fd);

	if (err != 0) {
		free(resp);
		return -err;
	}
	info->fh = fd;
	
	free(resp);

	return 0;
}

int ndfs_unlink(const char *path)
{
	log_function("Path is: %s", path);
	return 0;
}

int ndfs_truncate(const char *path, off_t newsize)
{
	log_function("Paths is: %s", path);
	return 0;
}

int ndfs_open(const char *path, struct fuse_file_info *info)
{
	log_function("Paths is: %s", path);
	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(OPEN);
	uint32_t len = sizeof(pathlen) + pathlen + sizeof(commandlen)
		+ commandlen;
	char buf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t len_n = htonl(len);

	memcpy(buf, &len_n, sizeof(len_n));
	memcpy(buf + sizeof(len_n), &commandlen_n, sizeof(commandlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n), OPEN, commandlen);
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen,
	       &pathlen_n, sizeof(pathlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen
	       + sizeof(pathlen_n), path, pathlen);
	
	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, buf, len + sizeof(len));
	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);

	check_kill(resp_len == sizeof(uint32_t), "Why would this happen?");
	uint32_t err = *(uint32_t*) resp;
	err = ntohs(err);
	if (err == 0) {
		log_info("opened: %s", path);
	} else {
		log_info("could not open: %s", path);
	}

	free(resp);
	return -err;
}

int ndfs_read(const char *path, char *buf, size_t size, off_t off,
	    struct fuse_file_info *info)
{
	log_function("path: %s", path);

	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(READ);
	uint32_t len = pathlen + sizeof (pathlen) +
		commandlen + sizeof(commandlen) + sizeof(size) + sizeof(off);
	char sendbuf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t size_n = htonl(size);
	uint32_t off_n = htonl(off);
	uint32_t len_n = htonl(len);

	char *ptr = sendbuf;
	memcpy(ptr, &len_n, sizeof(len_n));
	ptr += sizeof(len_n);
	memcpy(ptr, &commandlen_n, sizeof(commandlen_n));
	ptr += sizeof(commandlen_n);
	memcpy(ptr, READ, commandlen);
	ptr += commandlen;
	memcpy(ptr, &pathlen_n, sizeof(pathlen_n));
	ptr += sizeof(pathlen_n);
	memcpy(ptr, path, pathlen);
	ptr += pathlen;
	memcpy(ptr, &size_n, sizeof(size_n));
	ptr += sizeof(size_n);
	memcpy(ptr, &off_n, sizeof(off_n));
	ptr += sizeof(off_n);

	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, sendbuf, len + sizeof(len));

	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	ptr = resp;
	log_info("resplen is: %d\n", resp_len);
	if (resp_len == sizeof(uint32_t)) {
		uint32_t err = *(uint32_t*) (ptr);
		err = ntohl(err);
		return -err;
	}
	uint32_t datalen = *(uint32_t*) (ptr + (sizeof(uint32_t)));
	datalen = ntohl(datalen);
	char *data = (ptr + 2 * (sizeof(uint32_t)));
	memcpy(buf, data, datalen);

	return datalen;
}

int ndfs_write(const char *path, const char *buf, size_t size, off_t off,
	     struct fuse_file_info *info)
{
	log_function("Path is: %s, size is: %zd, offset is: %zd", path,
		     size, off);

	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(WRITE);
	uint32_t len = pathlen + sizeof(pathlen) + commandlen
		+ sizeof(commandlen) + sizeof(size) + size + sizeof(off);

	uint32_t len_n = htonl(len);
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t size_n = htonl(size);
	uint32_t off_n = htonl(off);

	int total_len = 0;
	char sendbuf[len + sizeof(len)];
	memcpy(sendbuf, &len_n, sizeof(len_n));
	total_len += sizeof(len_n);
	memcpy(sendbuf + total_len, &commandlen_n, sizeof(commandlen_n));
	total_len += sizeof(commandlen);
	memcpy(sendbuf + total_len, WRITE, commandlen);
	total_len += commandlen;
	memcpy(sendbuf + total_len, &pathlen_n, sizeof(pathlen_n));
	total_len += sizeof(pathlen);
	memcpy(sendbuf + total_len, path, pathlen);
	total_len += pathlen;
	memcpy(sendbuf + total_len, &size_n, sizeof(size_n));
	total_len += sizeof(size_n);
	memcpy(sendbuf + total_len, buf, size);
	total_len += size;
	memcpy(sendbuf + total_len, &off_n, sizeof(off_n));
	total_len += sizeof(off_n);


	print_ch(sendbuf, len + sizeof(len));
	print_d(sendbuf, len + sizeof(len));

	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, sendbuf, len + sizeof(len));
	int resp_len;
	void *resp = recv_from_sock(glob->sockfd, &resp_len);
	if (resp == NULL) {
		return -EPERM;
	}
	uint32_t err = *(uint32_t*) resp;
	err = ntohl(err);
	if (err != 0) {
		log_warning("Err: %d\n", err);
		return -err;
	}
	uint32_t n = *(uint32_t*) ((char*) resp + sizeof(uint32_t));
	n = ntohl(n);
	return n;
}




int ndfs_release(const char *path, struct fuse_file_info *info)
{
	log_function("Path is: %s", path);
	uint32_t pathlen = strlen(path);
	uint32_t commandlen = strlen(RELEASE);
	uint32_t len = sizeof(pathlen) + pathlen + sizeof(commandlen)
		+ commandlen;
	char buf[len + sizeof(len)];
	uint32_t pathlen_n = htonl(pathlen);
	uint32_t commandlen_n = htonl(commandlen);
	uint32_t len_n = htonl(len);

	memcpy(buf, &len_n, sizeof(len_n));
	memcpy(buf + sizeof(len_n), &commandlen_n, sizeof(commandlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n), RELEASE, commandlen);
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen,
	       &pathlen_n, sizeof(pathlen_n));
	memcpy(buf + sizeof(len_n) + sizeof(commandlen_n) + commandlen
	       + sizeof(pathlen_n), path, pathlen);
	
	struct global *glob = get_glob();
	send_to_sock(glob->sockfd, buf, len + sizeof(len));
	return 0;
}

