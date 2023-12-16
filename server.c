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

typedef enum {TCP, UDP} protocol;
#define BUFFER_SIZE 40
#define REPLY_SIZE 2200
#define CODE_SIZE 3
#define MAX_ARG_SIZE 24

#define FALSE 0
#define TRUE 1

int verbose = FALSE;

char buffer[BUFFER_SIZE];
char reply_buf[REPLY_SIZE];
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
 * Send the contents of the reply buffer to the stored address through the given protocol.
*/
void reply(protocol p, size_t length) {
    if(p == UDP) {
        n = sendto(fd_udp, reply_buf, length, 0, (struct sockaddr*)&addr, addrlen);
        if(n == -1) /*error*/ exit(1);
    }
    else if(p == TCP) {
        n = write(tcp_connection, reply_buf, length);
        if(n == -1) /*error*/ exit(1);
    }
}

/**
 * Send back an error message to the client.
*/
void reply_error(protocol p) {
    if(p == UDP) {
        n = sendto(fd_udp, "ERR\n", 4, 0, (struct sockaddr*)&addr, addrlen);
        if(n == -1) /*error*/ exit(1);
    }
    else if(p == TCP) {
        n = write(tcp_connection, "ERR\n", 4);
        if(n == -1) /*error*/ exit(1);
    }
}

/**
 * Take a code, a status, and optional arguments, and concatenate them all in the reply char array.
 * Return size of the resulting string.
*/
size_t build_reply(char* reply_code, char* status, char** args) {
    size_t offset, total = 0;
    char* cursor = reply_buf;
    char** arg_cursor = args;

    offset = strlen(reply_code);
    total += offset + 1;
    memcpy(cursor, reply_code, offset);
    cursor += offset;
    *cursor = ' ';
    cursor++;

    offset = strlen(status);
    total += offset + 1;
    memcpy(cursor, status, offset);
    cursor += offset;
    *cursor = ' ';
    cursor++;

    if(args == NULL) {
        cursor--;
        *cursor = '\n';
        return total;
    }

    while (*arg_cursor != NULL) {
        offset = strlen(*arg_cursor);
        total += offset + 1;
        memcpy(cursor, *arg_cursor, offset);
        cursor += offset;
        *cursor = ' ';
        cursor++;
        arg_cursor++;
    }

    cursor--;
    *cursor = '\n';
    return total;
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

/**
 * Check if a directory with path as its pathname exists.
 * Return 1 if it does, 0 otherwise.
*/
int directory_exists(const char *path) {
    struct stat buf;
    if (stat(path, &buf) != 0)
        return FALSE;

    if(S_ISDIR(buf.st_mode))
        return TRUE;
    return FALSE;
}

/**
 * Check if the user with uid is registered.
 * Return 1 if they are, 0 otherwise.
*/
int user_is_registered(char *uid) {
    char uid_path[13], pass_path[29];

    sprintf(uid_path, "USERS/%s", uid);
    sprintf(pass_path, "USERS/%s/%s_pass.txt", uid, uid);

    return directory_exists(uid_path) && (access(pass_path, F_OK) == 0);
}

/**
 * Check if the user with uid is logged in.
 * Return 1 if they are, 0 otherwise.
*/
int user_is_logged_in(char *uid) {
    char login_path[30];

    sprintf(login_path, "USERS/%s/%s_login.txt", uid, uid);

    return access(login_path, F_OK) == 0;
}

/**
 * Check if the argument password matches the arguments uid.
 * Return 1 if it does, 0 if not.
*/
int is_users_password(char *uid, char *password) {
    char pass_path[29], stored_password[9];
    FILE *pass_file = NULL;

    sprintf(pass_path, "USERS/%s/%s_pass.txt", uid, uid);

    pass_file = fopen(pass_path, "r");

    if(pass_file == NULL)
        return FALSE;

    n = fread(stored_password, 1, 8, pass_file);
    if (n == -1) /*error*/ exit(1);
    fclose(pass_file);
    stored_password[8] = '\0';

    return strcmp(password, stored_password) == 0;
}

/**
 * Create the necessary directories and password file to register the user.
*/
void register_user(char *uid, char *password) {
    char uid_path[13], pass_path[29], hosted_path[20], bidded_path[20];
    FILE *pass_file;

    sprintf(uid_path, "USERS/%s", uid);
    sprintf(pass_path, "USERS/%s/%s_pass.txt", uid, uid);
    sprintf(hosted_path, "USERS/%s/HOSTED", uid);
    sprintf(bidded_path, "USERS/%s/BIDDED", uid);

    mkdir(uid_path, 0777);
    mkdir(hosted_path, 0777);
    mkdir(bidded_path, 0777);

    pass_file = fopen(pass_path, "w");
    n = fwrite(password, 1, 8, pass_file);
    if (n == -1) /*error*/ exit(1);
    fclose(pass_file);
}

/**
 * Create the user's login file in the appropriate directory.
*/
void log_user_in(char *uid) {
    char login_path[30];
    FILE *login_file;

    sprintf(login_path, "USERS/%s/%s_login.txt", uid, uid);

    login_file = fopen(login_path, "w");
    fclose(login_file);
}

/**
 * Delete the user's login file.
*/
void log_user_out(char *uid) {
    char login_path[30];
    sprintf(login_path, "USERS/%s/%s_login.txt", uid, uid);

    unlink(login_path);
}

/**
 * Delete the user's login and password files.
*/
void unregister_user(char *uid) {
    char pass_path[29];
    sprintf(pass_path, "USERS/%s/%s_pass.txt", uid, uid);

    unlink(pass_path);
    log_user_out(uid);
}

/**
 * Server's response to the login command.
*/
void login(char* uid, char* password) {
    char replyCode[] = "RLI";
    size_t len;
    
    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        reply_error(UDP);
        return;
    }

    if(!user_is_registered(uid)) {
        register_user(uid, password);
        len = build_reply(replyCode, "REG", NULL);
        reply(UDP, len);
        return;
    }

    if(!is_users_password(uid, password)) {
        len = build_reply(replyCode, "NOK", NULL);
        reply(UDP, len);
        return;
    }

    log_user_in(uid);
    len = build_reply(replyCode, "OK", NULL);
    reply(UDP, len);
}

void logout(char *uid, char *password) {
    char replyCode[] = "RLO";
    size_t len;

    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        reply_error(UDP);
        return;
    }

    if(!user_is_registered(uid)) {
        len = build_reply(replyCode, "UNR", NULL);
        reply(UDP, len);
        return;
    }

    if(!user_is_logged_in(uid) || !is_users_password(uid, password)) {
        len = build_reply(replyCode, "NOK", NULL);
        reply(UDP, len);
        return;
    }

    log_user_out(uid);
    len = build_reply(replyCode, "OK", NULL);
    reply(UDP, len);
}

void unregister(char *uid, char* password) {
    char replyCode[] = "RLO";
    size_t len;

    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        reply_error(UDP);
        return;
    }

    if(!user_is_registered(uid)) {
        len = build_reply(replyCode, "UNR", NULL);
        //reply(UDP, len);
        printf(reply_buf);
        return;
    }

    if(!user_is_logged_in(uid)) {
        len = build_reply(replyCode, "NOK", NULL);
        reply(UDP, len);
        printf(reply_buf);
        return;
    }

    unregister_user(uid);
    len = build_reply(replyCode, "OK", NULL);
    reply(UDP, len);
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
            else if(strcmp(code, "LOU") == 0) {
                sscanf(buffer, "%*s %s %s", arg1, arg2);
                logout(arg1, arg2);
            }
            else if(strcmp(code, "UNR") == 0) {
                sscanf(buffer, "%*s %s %s", arg1, arg2);
                unregister(arg1, arg2);
            }
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
            memset(reply_buf, 0, REPLY_SIZE);
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
            memset(reply_buf, 0, REPLY_SIZE);
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