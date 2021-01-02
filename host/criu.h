#ifndef CRIU_H
#define CRIU_H

#include <err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char MIGRATE_COMMAND_STRING[]        = "./criu.sh migrate -t %s -D check --shell-job -v0";
static char DUMP_COMMAND_STRING[]           = "./criu.sh dump -t %s -D check --shell-job -v0";
static char START_MIGRATED_COMMAND_STRING[] = "./criu.sh start -D check --shell-job --exec-cmd -v0 -- ";

static void criu_execute_command(char * cmd, int pid) {

    // Convert the pid to string format again
    char pid_str[10];
    snprintf(pid_str, 10, "%d", pid);

    // -2 for %s and +1 for the null-terminator
    int total_size = strlen(cmd) - 2 + strlen(pid_str) + 1; 

    char * command = malloc(total_size);
    snprintf(command, total_size, cmd, pid_str);

    // Make this an #ifdef DEBUG
    // printf("The new command is: %s\n", command);

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

void criu_start_migrated(int arguments, char * argv[]) {
    //  Determine the full size of the final string that goes into system()
    int total_size = strlen(START_MIGRATED_COMMAND_STRING) + 1; // +1 for the 0-terminator
    for(int i = 0; i < arguments; i++) {
        total_size += strlen(argv[i]);

        if((i+1) != arguments) // For the spaces between the arguments
            total_size += 1;
    }

    // We can now allocate the full command.
    char * command = malloc(total_size);

    // Copy over the first part of the command "./criu.sh start -D check --shell-job --exec-cmd -- " 
    int index = 0;
    int size = strlen(START_MIGRATED_COMMAND_STRING);
    memcpy(command, START_MIGRATED_COMMAND_STRING, size);
    index += size;

    // Now append the rest of the arguments after the first part of the command
    for(int i = 0; i < arguments; i++) {
        size = strlen(argv[i]);

        if((i+1) != arguments) {
            // With spaces
            snprintf(command + index, total_size - index, "%s ", argv[i]);
            index += size + 1;
        } else {
            // Last one without space
            snprintf(command + index, total_size - index, "%s", argv[i]);
            index += size;
        }			
    }

    // Make this an #ifdef DEBUG
    // printf("The new command is: %s\n", command);
    
    int res = system(command);
    if(res)
        errx(res, "Error: %d\n");

    free(command);
}

#endif /* CRIU_H */