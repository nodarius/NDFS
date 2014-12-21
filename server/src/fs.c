#include <sys/xattr.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "fs.h"

#define MAX_BYTES 10000

struct open_file {
        char *path;
        int sockfd;
};

static int openfile_cmp(const void *a, const void *b)
{
        const struct open_file *f1 = *(struct open_file**) a;
        const struct open_file *f2 = *(struct open_file**) b;
        return strcmp(f1->path, f2->path);
}

enum COMMAND {
        GETATTR,
        MKDIR,
        READDIR,
        OPEN,
        RELEASE,
        READ,
        WRITE,
        CREATE,
        RENAME,

        UNKNOWN,
        INVALID,
};

struct rename {
        char *oldpath;
        char *newpath;
};

struct write {
        char *filepath;
        int offset;
        int size;
        void *buf;
};

struct read {
        char *filepath;
        int offset;
        int size;
};

struct readdir {
        char *filepath;
};

struct mkdir {
        char *filepath;
};

struct getattr {
        char *filepath;
};

struct open {
        char *filepath;
};

struct release {
        char *filepath;
};


void print_d(void *ptr, int len)
{
	return;
        printf("printing:\n");
        int i;
        for (i = 0; i < len; i++) {
                printf("%d ", ((char*) ptr)[i]);
        }
        printf("\n");
}

void print_ch(void *ptr, int len)
{
	return;
        printf("printing:\n");
        int i;
        for (i = 0; i < len; i++) {
                printf("%c", ((char*) ptr)[i]);
        }
        printf("\n");
}

static void buf_lshrink(struct buffer *buf, int n)
{
	log_function("buflen: %d, n: %d", buf->len_l, n);
        check_kill(buf->len_l >= n, "check arithmetics.");
        check_kill(n >= 0, "check arithmetics.");
        buf->len_l -= n;
        char *start = (char*) buf->data + n;
        memmove(buf->data, start, buf->len_l);
}

static struct readdir *parse_readdir(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;

        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        command_len = ntohl(command_len);
        uint32_t path_len = *(uint32_t*) ((char*) buf->data + sizeof(len) +
                                          sizeof(command_len) + command_len);
        path_len = htonl(path_len);
        char *path = calloc(1, path_len + 1);
        memcpy(path, (char*) buf->data + sizeof(len) + sizeof(command_len)
               + command_len + sizeof(path_len), path_len);
        struct readdir *res = calloc(1, sizeof *res);
        res->filepath = path;
        buf_lshrink(buf, command_len + path_len + sizeof(command_len)
                    + sizeof(path_len) + sizeof(len));
        return res;
}

static struct mkdir *parse_mkdir(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;
        int buflen = buf->len_l;
        if (buflen < 4) {
                return NULL;
        }

        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        if (buflen < len) {
                return NULL;
        }

        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        uint32_t command_len_h = ntohl(command_len);
        uint32_t path_len = *(uint32_t*) ((char*) buf->data + sizeof(len) +
                                          sizeof(command_len_h) + command_len_h);
        uint32_t path_len_h = ntohl(path_len);
        char *path = calloc(1, path_len + 1);
        memcpy(path, (char*) buf->data + sizeof(len) + sizeof(command_len)
               + command_len_h + sizeof(path_len), path_len_h);
        struct mkdir *res = calloc(1, sizeof *res);
        res->filepath = path;
        buf_lshrink(buf, command_len_h + path_len_h + sizeof(command_len)
                    + sizeof(path_len) + sizeof(len));
        return res;
}

static char *extract_path(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;

        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        command_len = ntohl(command_len);

        uint32_t path_len = *(uint32_t*) ((char*) buf->data + sizeof(len) +
                                          command_len + sizeof(command_len));
        path_len = ntohl(path_len);

        char *path = calloc(1, path_len + 1);
        memcpy(path, (char*) buf->data + sizeof(len) +
               command_len + sizeof(command_len)
               + sizeof(path_len), path_len);

        buf_lshrink(buf, sizeof(len) + command_len + path_len
                    + sizeof(command_len) + sizeof(path_len));
        return path;
}


static struct release *parse_release(struct client_con *con)
{
        log_function();
        char *path = extract_path(con);
        struct release *res = calloc(1, sizeof *res);
        res->filepath = path;
        return res;
}

static struct write *parse_write(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;
        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        command_len = ntohl(command_len);

        uint32_t path_len = *(uint32_t*) ((char*) buf->data + sizeof(len)
                                          + command_len + sizeof(command_len));
        path_len = ntohl(path_len);
        char *path = calloc(1, path_len + 1);
        memcpy(path, (char*) buf->data + sizeof(len) + sizeof(command_len)
               + command_len + sizeof(path_len), path_len);
        uint32_t size = *(uint32_t*) ((char*) buf->data + sizeof(len)
                                      + command_len + sizeof(command_len)
                                      + sizeof(path_len) + path_len);
        size = ntohl(size);
        char *data =  ((char*) buf->data + sizeof(len)
                       + command_len + sizeof(command_len)
                       + sizeof(path_len) + path_len
                       + sizeof(size));
        uint32_t offset = *(uint32_t*) (data + size);
        offset = ntohl(offset);

        buf_lshrink(buf, len + sizeof(len));

        struct write *wrt = calloc(1, sizeof *wrt);
        wrt->size = size;
        wrt->offset = offset;
        wrt->buf = data;
        wrt->filepath = path;
        return wrt;
}

static struct read *parse_read(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;
        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        command_len = ntohl(command_len);

        uint32_t path_len = *(uint32_t*) ((char*) buf->data + sizeof(len)
                                          + command_len + sizeof(command_len));
        path_len = ntohl(path_len);

        char *path = calloc(1, path_len + 1);
        memcpy(path, (char*) buf->data + sizeof(len) + sizeof(command_len)
               + command_len + sizeof(path_len), path_len);
        uint32_t size =  *(uint32_t*) ((char*) buf->data + sizeof(len)
                                       + command_len + sizeof(command_len)
                                       + sizeof(path_len) + path_len);
        size = ntohl(size);
        uint32_t offset =  *(uint32_t*) ((char*) buf->data + sizeof(len)
                                         + command_len + sizeof(command_len)
                                         + sizeof(path_len) + path_len
                                         + sizeof(size));
        offset = ntohl(offset);
        buf_lshrink(buf, len + sizeof(len));

        struct read *rd = calloc(1, sizeof *rd);
        rd->offset = offset;
        rd->size = size;
        rd->filepath = path;

        return rd;
}

static struct open *parse_open(struct client_con *con)
{
        log_function();
        char *path = extract_path(con);
        struct open *res = calloc(1, sizeof *res);
        res->filepath = path;
        return res;
}

static struct getattr *parse_getattr(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;

        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        command_len = ntohl(command_len);

        uint32_t path_len = *(uint32_t*) ((char*) buf->data + sizeof(len) +
                                          command_len + sizeof(command_len));
        path_len = ntohl(path_len);

        char *path = calloc(1, path_len + 1);
        memcpy(path, (char*) buf->data + sizeof(len) +
               command_len + sizeof(command_len)
               + sizeof(path_len), path_len);

        struct getattr *res = calloc(1, sizeof *res);
        res->filepath = path;
        buf_lshrink(buf, sizeof(len) + command_len + path_len
                    + sizeof(command_len) + sizeof(path_len));
        return res;
}

static enum COMMAND get_command(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;
        if (buf->len_l == 0) {
                return INVALID;
        }
        if (buf->len_l <= 4) {
//              sentinel("len less then 4\n");
                return UNKNOWN;
        }


        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);

        if (buf->len_l < len + sizeof(len)) {
                return UNKNOWN;
        }

        uint32_t command_len = *(uint32_t*) ((char*)buf->data + sizeof(len));
        command_len = ntohl(command_len);

        char *command = (char*) buf->data + sizeof(len) + sizeof(command_len);

        if (!strncmp(command, "getattr", strlen("getattr"))) {
                return GETATTR;
        } else  if (!strncmp(command, "mkdir", strlen("mkdir"))) {
                return MKDIR;
        } else  if (!strncmp(command, "readdir", strlen("readdir"))) {
                return READDIR;
        } else  if (!strncmp(command, "open", strlen("open"))) {
                return OPEN;
        } else  if (!strncmp(command, "release", strlen("release"))) {
                return RELEASE;
        } else  if (!strncmp(command, "read", strlen("read"))) {
                return READ;
        } else  if (!strncmp(command, "write", strlen("getattr"))) {
                return WRITE;
        } else  if (!strncmp(command, "create", strlen("create"))) {
                return CREATE;
        } else  if (!strncmp(command, "rename", strlen("rename"))) {
                return RENAME;
        } 

        return INVALID;
}

static int recv_to_buffer(struct client_con *con)
{
        log_function();
        check_kill(con, "Null parameter.");

        uint32_t len;
        int n = recv(con->sockfd, &len, sizeof(len), 0);
        if (n <= 0) {
                return 0;
        }
        int len_h = ntohl(len);
        if (n != sizeof(len)) {
                sentinel("n was: %d\n", n); /* TODO */
        }

        char arr[len_h + sizeof(len)];
        memcpy(arr, &len, sizeof(len));
        int sockfd = con->sockfd;
        n = recv(sockfd, arr + sizeof(len), len_h, MSG_DONTWAIT);
        struct buffer *recbuf = &con->recbuf;
        check_kill(n == len_h, "Error in logic.");
        if (n > 0) {
                n += sizeof(len);
                recbuf->len_l += n;
                if (recbuf->len_l > recbuf->len_a) {
			recbuf->len_a = (recbuf->len_l + 1) * 2;
			
                        recbuf->data = realloc(recbuf->data, recbuf->len_a);
                        check_mem(recbuf->data);
                }
                void *dst = (char*) recbuf->data + recbuf->len_l - n;
                memcpy(dst, arr, n);
        } else if (n == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        sentinel("Error in logic.");
                }
        }
        return n;
}

static int send_from_buffer(struct client_con *con)
{
        log_function();
        check_kill(con, "Null parameter.");

        int sockfd = con->sockfd;
        struct buffer *sendbuf = &con->sendbuf;
        int n = send(sockfd, sendbuf->data, sendbuf->len_l, 0);
        if (n > 0) {
                buf_lshrink(sendbuf, n);
        } else if (n == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        sentinel("Error in logic.");
                }
        }
        log_info("sent: %d bytes\n", n);
        return n;
}

static int write_to_buffer(struct client_con *con, void *ptr, int size)
{
        log_function();
        struct buffer *buf = &con->sendbuf;
        buf->len_l += size;
        if (buf->len_l > buf->len_a) {
		buf->len_a = (buf->len_l + 1) * 2;
                buf->data = realloc(buf->data, buf->len_a);
                check_mem(buf->data);
        }
        void *dst = (char*) buf->data + buf->len_l - size;
        memcpy(dst, ptr, size);
        return 1;
}

int fs_send(struct client_con *con)
{
        log_function();
        return send_from_buffer(con);
}

static int is_visible(const char *ip, char *name)
{
	char filepath[strlen(name) + 2];
	filepath[strlen(name) + 1] = 0;
	filepath[0] = '/';
	memcpy(filepath + 1, name, strlen(name));

	char tmp[100];
	sprintf(tmp, "user.%s", ip);
	char res[100];
	bzero(res, 100);
	int n = getxattr(filepath, tmp, res, 100);
	if (n < 0) {
		return 0;
	}
	return 1;
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

int is_first_level(const char *filepath)
{
	if (!strcmp(filepath, "/")) {
		return 0;
	}
	
        int count = 0;
        int i = 0;
        for (i = 0; i < strlen(filepath); i++) {
                if (filepath[i] == '/') {
                        count++;
                }
                if (count > 1) {
                        return 0;
                }
        }
        return 1;
}



static int do_getattr(struct client_con *con)
{
        log_function();
        struct getattr *getattr = parse_getattr(con);
        char *path = getattr->filepath;
        struct stat st;
        int n = stat(path, &st);
        uint32_t size = st.st_size;
        uint32_t mode = st.st_mode;

	if (n != -1 && is_first_level(path)) {
		if (!is_visible(get_peer_ip(con->sockfd), &path[1])) {
			n = -1;
		}
	}


        if (n == -1) {  /* probably no such file */
                int len = 0;
                int len_n = htonl(len);
                write_to_buffer(con, &len_n, sizeof(len));
        } else {

                uint32_t size_n = htonl(size);
                uint32_t mode_n = htonl(mode);

                uint32_t len = sizeof(size) + sizeof(mode);
                uint32_t len_n = htonl(len);
                char buf[len + sizeof(len)];
                memcpy(buf, &len_n, sizeof(len_n));
                memcpy(buf + sizeof(len_n), &size_n, sizeof(size_n));
                memcpy(buf + sizeof(len_n) + sizeof(size_n), &mode_n,
                       sizeof(mode_n));
                write_to_buffer(con, buf, len + sizeof(len));

        }
        return 1;
}

static int do_mkdir(struct client_con *con)
{
        log_function();
        struct mkdir *mdr = parse_mkdir(con);
        char *path = mdr->filepath;
        int first_level = is_first_level(path);

        int st = mkdir(path, 0755);
        if (st < 0 && errno == EEXIST && first_level) {
                uint32_t status_n = htonl(0);
                uint32_t len = sizeof(status_n);
                uint32_t len_n = htonl(len);
                char buf[len + sizeof(len)];
                memcpy(buf, &len_n, sizeof(len_n));
                memcpy(buf + sizeof(len_n), &status_n,
                       sizeof(status_n));
                write_to_buffer(con, buf, len + sizeof(len));
                log_info("mkdir successfull: %s\n", path);
                char *ip = get_peer_ip(con->sockfd);
                char tmp[100];
                sprintf(tmp, "user.%s", ip);
                int n = setxattr(path, tmp, "reader", strlen("reader"), 0);
                if (n < 0) {
                        perror("setxattr\n");
                }
		free(mdr->filepath);
		free(mdr);
                return 1;
        }

        if (st < 0) {
                int len = 0;
                int len_n = htonl(len);
                write_to_buffer(con, &len_n, sizeof(len));
                log_info("could not mkdir: %s", path);
        } else {
                uint32_t status_n = htonl(0);
                uint32_t len = sizeof(status_n);
                uint32_t len_n = htonl(len);
                char buf[len + sizeof(len)];
                memcpy(buf, &len_n, sizeof(len_n));
                memcpy(buf + sizeof(len_n), &status_n,
                       sizeof(status_n));
                write_to_buffer(con, buf, len + sizeof(len));
                log_info("mkdir successfull: %s\n", path);
                if (first_level) {
                        char *ip = get_peer_ip(con->sockfd);
                        char buf[100];
                        sprintf(buf, "user.%s", ip);
                        int n = setxattr(path, buf, "owner", strlen("owner"), 0);
                        if (n < 0) {
                                perror("setxattr\n");
                        }
                }
        }
	free(mdr->filepath);
	free(mdr);
        return 1;
}

static int do_create(struct client_con *con)
{
        log_function();
        char *path = extract_path(con);
        struct release *res = calloc(1, sizeof *res);
        res->filepath = path;
        log_info("Path is: %s", path);
        int n = creat(path, 0777);
        check_kill(n >= 0, "Could not creat\n"); /* TODO */
        uint32_t err = 0;
        if (n < 0) {
                err = errno;
        }
        struct open_file *of = calloc(1, sizeof *of);
        of->sockfd = n;
        of->path = strdup(path);
        if (!con->open_files) {
                con->open_files = vec_new(openfile_cmp);
        }
        vec_add(con->open_files, of);
        uint32_t fd = n;
        uint32_t len = sizeof(err) + sizeof(fd);
        len = htonl(len);
        fd = htonl(fd);
        err = htonl(err);
        write_to_buffer(con, &len, sizeof(len));
        write_to_buffer(con, &err, sizeof(err));
        write_to_buffer(con, &fd, sizeof(fd));
        return 1;
}

static struct rename *parse_rename(struct client_con *con)
{
        log_function();
        struct buffer *buf = &con->recbuf;

        uint32_t len = *(uint32_t*) buf->data;
        len = ntohl(len);
        print_ch(buf->data, len + sizeof(len));
        print_d(buf->data, len + sizeof(len));

        uint32_t command_len = *(uint32_t*) ((char*) buf->data + sizeof(len));
        command_len = ntohl(command_len);

        uint32_t oldlen = *(uint32_t*) ((char*) buf->data + sizeof(len)
                                        + sizeof(command_len) + command_len);
        oldlen = ntohl(oldlen);
        char *oldpath = ((char*) buf->data + sizeof(len)
                         + sizeof(command_len) + command_len
                         + sizeof(oldlen));
        uint32_t newlen = *(uint32_t*) ((char*) buf->data + sizeof(len)
                                        + sizeof(command_len) + command_len
                                        + sizeof(oldlen) + oldlen);
        newlen = ntohl(newlen);
        char *newpath = ((char*) buf->data + sizeof(len)
                         + sizeof(command_len) + command_len
                         + sizeof(oldlen) + oldlen
                         + sizeof(newlen));

        buf_lshrink(buf, len + sizeof(len));

        struct rename *rnm = calloc(1, sizeof *rnm);
        rnm->oldpath = calloc(1, oldlen + 1);
        memcpy(rnm->oldpath, oldpath, oldlen);
        rnm->newpath = calloc(1, newlen + 1);
        memcpy(rnm->newpath, newpath, newlen);
        return rnm;

}

static int do_rename(struct client_con *con)
{
        struct rename *rnm = parse_rename(con);
        uint32_t status = rename(rnm->oldpath, rnm->newpath);
        status *= -1;
        status = htonl(status);
        uint32_t len = sizeof(status);
        uint32_t len_n = htonl(len);
        write_to_buffer(con, &len_n, sizeof(len));
        write_to_buffer(con, &status, sizeof(status));
        return 1;
}

static int do_write(struct client_con *con)
{
        log_function();
        check_kill(con->open_files, "Why would this happen?");
        struct write *wrt = parse_write(con);
        char *path = wrt->filepath;
        int offset = wrt->offset;

        struct open_file key;
        key.path = path;
        struct open_file *val = vec_find(con->open_files, &key);
        if (!val) {
                uint32_t nwriten = htonl(0);
                uint32_t err = htonl(ENOENT);
                uint32_t len = htonl(sizeof(err) + sizeof(nwriten));
                write_to_buffer(con, &len, sizeof(len));
                write_to_buffer(con, &err, sizeof(err));
                write_to_buffer(con, &nwriten, sizeof(nwriten));
                /* NO such file */
		free(wrt);
                return 1;
        }
        lseek(val->sockfd, offset, SEEK_SET);
        uint32_t nwriten = write(val->sockfd, wrt->buf, wrt->size);
        uint32_t err;
        if (nwriten < 0) {
                sentinel("could not write."); /* TODO */
                err = htonl(errno);
        } else {
                err = 0;
        }
        uint32_t len = htonl(sizeof(err) + sizeof(nwriten));
        nwriten = htonl(nwriten);
        write_to_buffer(con, &len, sizeof(len));
        write_to_buffer(con, &err, sizeof(err));
        write_to_buffer(con, &nwriten, sizeof(nwriten));
	free(wrt);
        return 1;
}

static int do_read(struct client_con *con)
{
        log_function();
        check_kill(con->open_files, "Why would this happen?");
        struct read *rd = parse_read(con);
        int size = rd->size;
        int off = rd->offset;
        char *path = rd->filepath;

        struct open_file key;
        key.path = path;
        struct open_file *val = vec_find(con->open_files, &key);
        if (!val) {
                uint32_t err = htonl(ENOENT);
                uint32_t len = htonl(sizeof(err));
                write_to_buffer(con, &len, sizeof(len));
                write_to_buffer(con, &err, sizeof(err));
                /* NO such file */
                return 1;
        }

        lseek(val->sockfd, off, SEEK_SET);
        char buffer[size];
        int nread = read(val->sockfd, buffer, size);
        print_ch(buffer, nread);

        if (nread < 0) {
                uint32_t err = htonl(errno);
                uint32_t len = htonl(sizeof(err));
                write_to_buffer(con, &len, sizeof(len));
                write_to_buffer(con, &err, sizeof(err));
                return 1;
        }
        uint32_t err = 0;
        uint32_t len = sizeof(err) + sizeof(nread) + nread;
        uint32_t len_n = htonl(len);
        write_to_buffer(con, &len_n, sizeof(len_n));
        write_to_buffer(con, &err, sizeof(err));
        uint32_t nread_n = htonl(nread);
        write_to_buffer(con, &nread_n, sizeof(nread_n));
        write_to_buffer(con, buffer, nread);

        return 1;

}

static int do_release(struct client_con *con)
{
        log_function();
        struct release *rel = parse_release(con);
        char *path = rel->filepath;
        check_kill(con->open_files, "Why would this happen?");
        struct open_file key;
        key.path = path;
        struct open_file *val = vec_find(con->open_files, &key);
        if (!val) {
                return 1;
        }
        check_kill(val, "Already released?"); /* TODO */
        vec_remove(con->open_files, val);
        close(val->sockfd);
        free(val->path);
        free(val);
        return 1;
}

static int do_open(struct client_con *con)
{
        log_function();
        struct open *opn = parse_open(con);
        char *path = opn->filepath;
        umask(0);
        int sockfd = open(path, O_RDWR, S_IRWXU);
        uint32_t err;
        if (sockfd < 0) {
                perror("Could not open.");
                err = htonl(errno);
        } else {
                err = 0;
                if (!con->open_files) {
                        con->open_files = vec_new(openfile_cmp);
                }
                struct open_file *of = calloc(1, sizeof *of);
                of->sockfd = sockfd;
                of->path = strdup(path);

//                print_vec(con->open_files);
                vec_add(con->open_files, of);
		//              print_vec(con->open_files);

        }
        int len = sizeof(err);
        int len_n = htonl(len);
        write_to_buffer(con, &len_n, sizeof(len));
        write_to_buffer(con, &err, sizeof(err));

        return 1;
}

static int do_readdir(struct client_con *con)
{
        struct readdir *rdir = parse_readdir(con);
        char *path = rdir->filepath;

	int is_root = 0;
	const char *ip;
	if (!strcmp(path, "/")) {
		is_root = 1;
		ip = get_peer_ip(con->sockfd);
	}
	
        DIR *dir = opendir(path);
        struct dirent *dp;
        struct buffer *sendbuf = &con->sendbuf;
        int total_len = 0;
        int index = sendbuf->len_l;
        write_to_buffer(con, &total_len, sizeof(total_len));

        while (dir) {
                dp = readdir(dir);
                if (!dp) {
                        break;
                }
                char *name = dp->d_name;
		if (is_root) {
			if (!is_visible(ip, name)) {
				continue;
			}
		}

                int len = strlen(name);
                uint32_t len_n = htonl(len);
                write_to_buffer(con, &len_n, sizeof(len));
                write_to_buffer(con, name, len);
                total_len += sizeof(len);
                total_len += len;

        }
        char *dst = &((char*) sendbuf->data) [index];
        total_len = htonl(total_len);
        memcpy(dst, &total_len, sizeof(total_len));
        closedir(dir);
        log_info("readdir successfull\n");

        return 1;

}

int fs_recv(struct client_con *con)
{
        log_function();
        if (recv_to_buffer(con) <= 0) {
                return 0;
        }

        enum COMMAND command = get_command(con);
        if (command == UNKNOWN) {
                log_warning("Unknown command\n");
                return 1;
        } else if (command == GETATTR) {
                return do_getattr(con);
        } else if (command == MKDIR) {
                return do_mkdir(con);
        } else if (command == READDIR) {
                return do_readdir(con);
        } else if (command == OPEN) {
                return do_open(con);
        } else if (command == RELEASE) {
                return do_release(con);
        } else if (command == READ) {
                return do_read(con);
        } else if (command == WRITE) {
                return do_write(con);
        } else if (command == CREATE) {
                return do_create(con);
        } else if (command == RENAME) {
                return do_rename(con);
        } else {
                return 0;
        }

        return 0;
}
