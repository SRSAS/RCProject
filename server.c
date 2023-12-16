#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/select.h>
#include <getopt.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define PORT "58100"
#define MAX_TCP_CONNECTION_QUEUE 10

#define BUFFER_SIZE 40
#define CODE_SIZE 3
#define MAX_ARG_SIZE 24

#define FALSE 0
#define TRUE 1

int verbose = FALSE;

char buffer[BUFFER_SIZE];
char code[CODE_SIZE + 1];

//Sockets' variables
int fd_udp, fd_tcp, tcp_connection, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res_udp, *res_tcp;
struct sockaddr_in addr;

//Select variables
fd_set sockets, to_read;
int readable_count;

void initializeSockets(char *port) {
    //UDP socket setup
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0); //UDP socket
    if(fd_udp == -1) /*error*/ exit(1);
    memset(&hints, 0, sizeof hints);

    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, port, &hints, &res_udp);
    if(errcode != 0) /*error*/ exit(1);

    n = bind(fd_udp, res_udp->ai_addr, res_udp->ai_addrlen);
    if(n == -1) /*error*/ exit(1);

    //TCP socket setup
    fd_tcp = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
    if (fd_tcp == -1) exit(1); //error

    hints.ai_socktype = SOCK_STREAM; //TCP socket

    errcode = getaddrinfo(NULL, port, &hints, &res_tcp);
    if((errcode) != 0) /*error*/ exit(1);

    n = bind(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
    if(n == -1) /*error*/ exit(1);
    
    if(listen(fd_tcp, MAX_TCP_CONNECTION_QUEUE) ==- 1) /*error*/ exit(1);
}

/**
 * Check if a string is composed only of digits.
 * Return 1 if true, 0 if false.
*/
int string_is_number(char* string) {
    for (int i = 0; i < strlen(string); i++)
        if(!isdigit(string[i]))
            return FALSE;
    return TRUE;
}

/**
 * Check if a string is composed only of alphanumeric characters.
 * Return 1 if true, 0 if false.
*/
int string_is_alnum(char* string) {
    for (int i = 0; i < strlen(string); i++)
        if(!isalnum(string[i]))
            return FALSE;
    return TRUE;
}

void login(char* uid, char* password) {
    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        n = sendto(fd_udp, "ERR\n", 4, 0, (struct sockaddr*)&addr, addrlen);
        if(n == -1) /*error*/ exit(1);
    }

    //Check if UID already exists
    //If UID exists, check if uid_pass.txt exists
    //  If uid_pass.txt exists, check password against uid_pass.txt
    //      If password is the same, check if there fopen uid_login.txt, and send RLI OK to client
    //      Else if password is NOT the same, send RLI NOK to client
    //  If uid_pass.txt does NOT exist, fopen uid_pass.txt, write password, and send RLI REG to client
    //If UID does NOT exist, create UID directory, fopen uid_pass.txt, write password, and send RLI REG to client
}


int main(int argc, char *argv[]) {
    int opt;
    char port[5] = PORT;
    char arg1[MAX_ARG_SIZE + 1], arg2[MAX_ARG_SIZE + 1], arg3[MAX_ARG_SIZE + 1], arg4[MAX_ARG_SIZE + 1];

    while ((opt = getopt(argc, argv, "p:v")) != -1) {
        switch (opt) {
            case 'p':
                strcpy(port, optarg);
                break;
            case 'v':
                verbose = TRUE;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    mkdir("USERS", 0777);
    mkdir("AUCTIONS", 0777);
    initializeSockets(port);

    FD_ZERO(&sockets);
    FD_SET(fd_udp, &sockets);
    FD_SET(fd_tcp, &sockets);

    while (1) {
        to_read = sockets;
        readable_count = select(FD_SETSIZE, &to_read, (fd_set *)NULL, (fd_set *)NULL, (struct timeval*)NULL);

        if(readable_count == -1) {
            perror("select");
            exit(1);
        }

        if(FD_ISSET(fd_udp, &to_read)) {
            n = recvfrom(fd_udp, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
            if(n == -1) /*error*/ exit(1);

            if(n > 20 || n < 4) {}

            sscanf(buffer, "%s", code);

            if(strcmp(code, "LIN") == 0) {
                sscanf(buffer, "%*s %s %s", arg1, arg2);
                login(arg1, arg2);
            }
            else if(strcmp(code, "LOU") == 0) {}
            else if(strcmp(code, "UNR") == 0) {}
            else if(strcmp(code, "LMA") == 0) {}
            else if(strcmp(code, "LMB") == 0) {}
            else if(strcmp(code, "LST") == 0) {}
            else if(strcmp(code, "SRC") == 0) {}
            else {
                n = sendto(fd_udp, "ERR\n", 4, 0, (struct sockaddr*)&addr, addrlen);
                if(n == -1) /*error*/ exit(1);
            }

            //Reset data
            n = 0;
            memset(buffer, 0, BUFFER_SIZE);
            memset(code, 0, CODE_SIZE + 1);
            memset(arg1, 0, MAX_ARG_SIZE + 1);
            memset(arg2, 0, MAX_ARG_SIZE + 1);
            memset(arg3, 0, MAX_ARG_SIZE + 1);
            memset(arg4, 0, MAX_ARG_SIZE + 1);

        }

        if (FD_ISSET(fd_tcp, &to_read)) {
            tcp_connection = accept(fd_tcp, (struct sockaddr*)&addr, &addrlen);
            if(tcp_connection == -1 ) /*error*/ exit(1);

            n = read(tcp_connection, buffer, BUFFER_SIZE);
            if(n == -1) /*error*/ exit(1);

            sscanf(buffer, "%s", code);

            if(strcmp(code, "OPA") == 0) {}
            else if(strcmp(code, "CLS") == 0) {}
            else if(strcmp(code, "SAS") == 0) {}
            else if(strcmp(code, "BID") == 0) {}

            close(tcp_connection);

            //Reset data
            n = 0;
            memset(buffer, 0, BUFFER_SIZE);
            memset(code, 0, CODE_SIZE + 1);
            memset(arg1, 0, MAX_ARG_SIZE + 1);
            memset(arg2, 0, MAX_ARG_SIZE + 1);
            memset(arg3, 0, MAX_ARG_SIZE + 1);
            memset(arg4, 0, MAX_ARG_SIZE + 1);
        }
    }

    freeaddrinfo(res_udp);
    freeaddrinfo(res_tcp);
    close(fd_udp);
    close(fd_tcp);

    return 0;
}