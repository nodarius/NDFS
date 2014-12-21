#ifndef COMMON_H
#define COMMON_H

#include "logger.h"

struct global {
	int sockfd;
};

char *get_parent_path(const char *path);

#endif
