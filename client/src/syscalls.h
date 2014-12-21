#ifndef SYSCALLS_H
#define SYSCALLS_H

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>

#include "logger.h"

void *ndfs_init(struct fuse_conn_info *conn);


void ndfs_destroy(void *private_data);

int ndfs_getattr(const char *path, struct stat *stbuf);

int ndfs_mkdir(const char *path, mode_t mode);

int ndfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		      off_t offset, struct fuse_file_info *fi);


int ndfs_rename(const char *oldpath, const char *newpath);

int ndfs_open(const char *path, struct fuse_file_info *info);

int ndfs_utime(const char *path, struct utimbuf *ubuf);

int ndfs_create(const char *path, mode_t mode, struct fuse_file_info *info);
int ndfs_truncate(const char *path, off_t newsize);
int ndfs_unlink(const char *path);

int ndfs_read(const char *path, char *buf, size_t size, off_t off,
	    struct fuse_file_info *info);

int ndfs_write(const char *path, const char *buf, size_t size, off_t off,
	     struct fuse_file_info *info);


int ndfs_release(const char *path, struct fuse_file_info *info);

int ndfs_opendir(const char *path, struct fuse_file_info *fi);

int ndfs_releasedir(const char *path, struct fuse_file_info *fi);


#endif
