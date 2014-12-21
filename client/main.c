#include <stdio.h>
#include "src/syscalls.h"
#include "src/logger.h"

#pragma GCC diagnostic ignored "-Wunused-function"


void start_logging()
{
	setlogmask(LOG_UPTO (LOG_WARNING));
	openlog("ndfs", LOG_CONS | LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_LOCAL1);
	log_info("ndfs started."); /* useful when grepping log */
}


struct fuse_operations ndfs_oper = {
	.init = ndfs_init,
	.destroy = ndfs_destroy,
	.mkdir = ndfs_mkdir,
	.getattr = ndfs_getattr,
	.readdir = ndfs_readdir,
	.rename = ndfs_rename,
	.read = ndfs_read,
	.write = ndfs_write,
	.open = ndfs_open,
	.release = ndfs_release,
	.create = ndfs_create,
	.truncate = ndfs_truncate,
	.utime = ndfs_utime,

	.unlink = ndfs_unlink,
	
};


int main(int argc, char **argv)
{
	printf("Hello world\n");
	start_logging();
	
	return fuse_main(argc, argv, &ndfs_oper, NULL);
}
