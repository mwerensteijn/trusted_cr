#ifndef CRIU_H
#define CRIU_H

#include <err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char MIGRATE_COMMAND_STRING[] = "./criu.sh migrate -t %s -D check --shell-job -v0";
static char DUMP_COMMAND_STRING[]    = "./criu.sh dump -t %s -D check --shell-job -v0";

static void criu_execute_command(char * cmd, int pid) {

    // Convert the pid to string format again
    char pid_str[10];
    snprintf(pid_str, 10, "%d", pid);

    // -2 for %s and +1 for the null-terminator
    int total_size = strlen(cmd) - 2 + strlen(pid_str) + 1; 

    char * command = malloc(total_size);
    snprintf(command, total_size, cmd, pid_str);

    // Make this an #ifdef DEBUG
    printf("The new command is: %s\n", command);

    int res = system(command);
    if(res)
        errx(res, "Error: %d\n", res);

    free(command);
}

void criu_dump(int pid) {
    criu_execute_command(DUMP_COMMAND_STRING, pid);
}

void criu_dump_migration_api(int pid) {
    criu_execute_command(MIGRATE_COMMAND_STRING, pid);
}

#endif /* CRIU_H */