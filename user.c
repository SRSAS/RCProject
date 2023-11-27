#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#define DEFAULT_IP "tejo.tecnico.ulisboa.pt"
#define DEFAULT_PORT "58000"
#define GROUP_NUMBER 100
#define LOGIN_MSG_SIZE 20
#define LOGOUT_MSG_SIZE 20
#define SAS_MSG_SIZE 8
#define UNR_MSG_SIZE 20
#define UID_SIZE 6
#define PWORD_SIZE 8
#define STATUS_SIZE 4
#define FILENAME_SIZE 25

int fd_udp, fd_tcp, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res_udp, *res_tcp;
struct sockaddr_in addr;
char buffer[128], userID[UID_SIZE + 1], password[PWORD_SIZE + 1];

void printUsage() {
    fprintf(stderr, "Usage: ./user [-n ASIP] [-p ASport]\n");
    exit(EXIT_FAILURE);
}

void login(char* uid, char* pword) {
    char message[LOGIN_MSG_SIZE], status[STATUS_SIZE], code[] = "LIN";
    char *cursor = message;
    size_t codeSize = strlen(code);

    memcpy(cursor, code, codeSize);

    cursor += codeSize;
    *cursor = ' ';
    cursor++;
    memcpy(cursor, uid, UID_SIZE);

    cursor += UID_SIZE;
    *cursor = ' ';
    cursor++;
    memcpy(cursor, pword, PWORD_SIZE);

    cursor += PWORD_SIZE;
    *cursor = '\0';

    n = sendto(fd_udp, message, LOGIN_MSG_SIZE, 0, res_udp->ai_addr, res_udp->ai_addrlen);
    if (n == -1) /*error*/ exit(EXIT_FAILURE);

    n = recvfrom(fd_udp, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen);
    if (n == -1) /*error*/ exit(EXIT_FAILURE);

    n = sscanf(message, "%s %s", NULL, status);
    if (n == EOF) /*error*/ exit(EXIT_FAILURE);

    if(strcmp(status, "OK") == 0) {
        printf("Successful login\n");
        strcpy(userID, uid);
        strcpy(password, pword);
    }
    else if(strcmp(status, "NOK") == 0)
        printf("Incorrect login\n");
    else if(strcmp(status, "REG") == 0) {
        printf("New user registered\n");
        strcpy(userID, uid);
        strcpy(password, pword);
    }
    else
        print("Unknown login status\n");
}

void logout() {
    char message[LOGOUT_MSG_SIZE], status[STATUS_SIZE], code[] = "LOU";
    char *cursor = message;
    size_t codeSize = strlen(code);

    memcpy(cursor, code, codeSize);

    cursor += codeSize;
    *cursor = ' ';
    cursor++;
    memcpy(cursor, userID, UID_SIZE);

    cursor += UID_SIZE;
    *cursor = ' ';
    cursor++;
    memcpy(cursor, password, PWORD_SIZE);

    cursor += PWORD_SIZE;
    *cursor = '\0';

    n = sendto(fd_udp, message, LOGOUT_MSG_SIZE, 0, res_udp->ai_addr, res_udp->ai_addrlen);
    if (n == -1) /*error*/ exit(EXIT_FAILURE);

    n = recvfrom(fd_udp, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen);
    if (n == -1) /*error*/ exit(EXIT_FAILURE);

    //memset(userID, 0, UID_SIZE + 1);
    //memset(password, 0, PWORD_SIZE + 1);

    if(strcmp(status, "OK") == 0)
        printf("Successful logout\n");
    else if(strcmp(status, "NOK") == 0)
        printf("User not logged in\n");
    else if(strcmp(status, "UNR") == 0)
        printf("Unknown user\n");
    else
        print("Unknown login status\n");
}

void unregister() {
    char message[UNR_MSG_SIZE], status[STATUS_SIZE], code[] = "UNR";
    char *cursor = message;
    size_t codeSize = strlen(code);

    memcpy(cursor, code, codeSize);

    cursor += codeSize;
    *cursor = ' ';
    cursor++;
    memcpy(cursor, userID, UID_SIZE);

    cursor += UID_SIZE;
    *cursor = ' ';
    cursor++;
    memcpy(cursor, password, PWORD_SIZE);

    cursor += PWORD_SIZE;
    *cursor = '\0';

    n = sendto(fd_udp, message, LOGOUT_MSG_SIZE, 0, res_udp->ai_addr, res_udp->ai_addrlen);
    if (n == -1) /*error*/ exit(EXIT_FAILURE);

    n = recvfrom(fd_udp, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen);
    if (n == -1) /*error*/ exit(EXIT_FAILURE);

    memset(userID, 0, UID_SIZE + 1);
    memset(password, 0, PWORD_SIZE + 1);

    if(strcmp(status, "OK") == 0)
        printf("Successful unregister\n");
    else if(strcmp(status, "NOK") == 0)
        printf("Incorrect unregister attempt\n");
    else if(strcmp(status, "UNR") == 0)
        printf("Unknown user\n");
    else
        print("Unknown login status\n");
}

void show_asset(char* aid) {
    char message[SAS_MSG_SIZE], status[STATUS_SIZE], filename[FILENAME_SIZE], code[] = "SAS";
    int file_size;

    n = connect(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
    if(n==-1) /*error*/exit(EXIT_FAILURE);

    
}

void initializeSockets(char* ip, char* port) {
    addrlen = sizeof(addr);
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (fd_udp == -1) /*error*/ exit(EXIT_FAILURE);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket

    errcode = getaddrinfo(ip, port, &hints, &res_udp);
    if (errcode != 0) /*error*/ exit(EXIT_FAILURE);


    fd_tcp = socket(AF_INET, SOCK_STREAM, 0); // UDP socket
    if (fd_tcp == -1) /*error*/ exit(EXIT_FAILURE);

    hints.ai_socktype = SOCK_STREAM; // UDP socket

    errcode = getaddrinfo(ip, port, &hints, &res_tcp);
    if (errcode != 0) /*error*/ exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    
    char *asIP = DEFAULT_IP;
    int num = atoi(DEFAULT_PORT);
    num += GROUP_NUMBER;
    char *asPort = (char *)malloc(5);
    sprintf(asPort, "%d", num);

    int opt;
    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
            case 'n':
                asIP = optarg;
                break;
            case 'p':
                asPort = optarg;
                break;
            default:
                printUsage();
                exit(EXIT_FAILURE);
        }
    }

    initializeSockets(asIP, asPort);

    while (1) {
        printf("Enter a message (or 'exit' to quit): ");
        fflush(stdout);

        char message[128];

        scanf("%s", message);

        if (strcmp(message, "login") == 0) {
            break;
        }

        if (strcmp(message, "logout") == 0) {
            break;
        }

        if (strcmp(message, "unregister") == 0) {
            break;
        }
        
        if (strcmp(message, "exit") == 0) {
            break;
        }
        
        if (strcmp(message, "open") == 0) {
            break;
        }

        if (strcmp(message, "close") == 0) {
            break;
        }

        if (strcmp(message, "myauctions") == 0 || strcmp(message, "ma"))  {
            break;
        }

        if (strcmp(message, "mybids") == 0  || strcmp(message, "mb")) {
            break;
        }

        if (strcmp(message, "list") == 0 || strcmp(message, "l")) {
            break;
        }

        if (strcmp(message, "show_asset") == 0 || strcmp(message, "sa")) {
            break;
        }

        if (strcmp(message, "bid") == 0 || strcmp(message, "b")) {
            break;
        }

        if (strcmp(message, "show_record" || strcmp(message, "sr")) == 0) {
            break;
        }

        n = sendto(fd_udp, message, strlen(message), 0, res_udp->ai_addr, res_udp->ai_addrlen);
        if (n == -1) /*error*/ exit(EXIT_FAILURE);

        n = recvfrom(fd_udp, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen);
        if (n == -1) /*error*/ exit(EXIT_FAILURE);

        write(1, "echo: ", 6);
        write(1, buffer, n);
    }

    freeaddrinfo(res_udp);
    freeaddrinfo(res_tcp);
    close(fd_udp);
    close(fd_tcp);
    free(asPort); // Free memory allocated for asPort
    return 0;
}
