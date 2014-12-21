#ifndef FS_H
#define FS_H

#include "connection.h"
#include "logger.h"


int fs_send(struct client_con *con);
int fs_recv(struct client_con *con);

#endif
