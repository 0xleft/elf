#define _GNU_SOURCE
#include <config.h>

#include <dlfcn.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pcap.h>

// EXECVE

int (*o_execve)(const char *, char *const argv[], char *const envp[]);
int execve(const char *path, char *const argv[], char *const envp[]) {
#ifdef VERBOSE
	printf("execve called\n");
#endif
    if(!o_execve)
        o_execve = dlsym(RTLD_NEXT, "execve");

    return o_execve(path, argv, envp);
}

// READDIR

struct dirent *(*o_readdir)(DIR *);
struct dirent *readdir(DIR *p) {
#ifdef VERBOSE
    printf("readdir called\n");
#endif
    if(!o_readdir)
        o_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *dir = o_readdir(p);
    return dir;
}

// UNLINK

int (*o_unlink)(const char *);
int unlink(const char *pathname) {
#ifdef VERBOSE
    printf("unlink called\n");
#endif
    if(!o_unlink)
        o_unlink = dlsym(RTLD_NEXT, "unlink");

    return o_unlink(pathname);
}

// UNLINKAT

int (*o_unlinkat)(int, const char *, int);
int unlinkat(int dirfd, const char * pathname, int flags) {
#ifdef VERBOSE
    printf("unlinkat called\n");
#endif
    if(!o_unlinkat)
        o_unlinkat = dlsym(RTLD_NEXT, "unlinkat");

    return o_unlinkat(dirfd, pathname, flags);
}

// WRITE
ssize_t (*o_write)(int, const void *, size_t);
ssize_t write(int fd, const void *xbuf, size_t count) {
#ifdef VERBOSE
    printf("write called\n");
#endif
    if(!o_write)
        o_write = dlsym(RTLD_NEXT, "write");

    return o_write(fd, xbuf, count);
}

// READ

ssize_t (*o_read)(int, void *, size_t);
ssize_t read(int fd, void *xbuf, size_t count) {
#ifdef VERBOSE
    printf("read called\n");
#endif
    if(!o_read)
        o_read = dlsym(RTLD_NEXT, "read");

    return o_read(fd, xbuf, count);
}