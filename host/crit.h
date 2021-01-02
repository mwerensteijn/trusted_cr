#ifndef CRIT_H
#define CRIT_H

#include <stdbool.h>
#include <sys/socket.h> 
#include <arpa/inet.h> 

#define PORT 50007

static bool connected = false;
static int sock = 0;
static struct sockaddr_in serv_addr; 

int crit_execute(int sock, char * command, char * buffer) {
    send(sock, command , strlen(command) , 0 ); 
    // printf("CRIU decode message sent: %s\n", command); 
    int valread = read( sock , buffer, 1024); 
	buffer[valread] = '\0';
    // printf("%s\n",buffer ); 
	return valread;
}

static bool connect_critserver() {
    if(connected)
        return connected;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        printf("\n Socket creation error \n"); 
        return false; 
    } 

    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 

    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) { 
        printf("\nInvalid address/ Address not supported \n"); 
        return false; 
    } 

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) { 
        printf("Connection to CRIT server failed.\n");
        printf("Is it running?\n"); 
        return false; 
    }

    connected = true;

    return connected;
}


static bool disconnect_critserver() {
    if(!connected)
        return true;

	close(sock);
    connected = false;

    return connected;
}

static bool decode_pid() {
    if(!connect_critserver())
        return false;

    char buffer[1024] = {0}; 
	char command[100];
	
	snprintf(command, 100, "decode -i check/pstree.img --pretty -o pstree.txt");
	crit_execute(sock, command, buffer);

	return true;
}

bool decode_checkpoint(int pid) {
    if(!connect_critserver())
        return false;


    char buffer[1024] = {0}; 
	char command[100];
	
	snprintf(command, 100, "decode -i check/core-%d.img --pretty -o core-%d.txt", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "decode -i check/pagemap-%d.img --pretty -o pagemap-%d.txt", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "decode -i check/mm-%d.img --pretty -o mm-%d.txt", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "decode -i check/files.img --pretty -o files.txt", pid, pid);
	crit_execute(sock, command, buffer);

	return true;
}

bool encode_checkpoint(int pid) {
    if(!connect_critserver())
        return false;

    char buffer[1024] = {0}; 
	char command[100];
	snprintf(command, 100, "encode -i modified_core.txt -o check/core-%d.img", pid, pid);
	crit_execute(sock, command, buffer);

	snprintf(command, 100, "encode -i modified_pagemap.txt -o check/pagemap-%d.img", pid, pid);
	crit_execute(sock, command, buffer);

	return true;
}

#endif /* CRIT_H */