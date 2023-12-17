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
#include <time.h>

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
size_t reply(protocol p, size_t length) {
    if(p == UDP)
        return sendto(fd_udp, reply_buf, length, 0, (struct sockaddr*)&addr, addrlen);
    else if(p == TCP)
        return write(tcp_connection, reply_buf, length);
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
 * Check if the auction with the argument aid exists.
 * Return 1 if it does, 0 if not.
*/
int auction_exists(char *aid) {
    char auction_path[13];

    sprintf(auction_path, "AUCTIONS/%s", aid);

    return access(auction_path, F_OK) == 0;
}

/**
 * Check if the auction with the argument aid has a file.
 * Return 1 if it does, 0 if not.
*/
int auction_has_file(char *aid) {
    char auction_path[13];
    DIR *auctions;
    struct dirent *auction_file;

    sprintf(auction_path, "AUCTIONS/%s", aid);

    auctions = opendir(auction_path);

    while ((auction_file = readdir(auctions)) != NULL) {
        if(strcmp(auction_file->d_name, ".") == 0 || strcmp(auction_file->d_name, "..") == 0)
            continue;
        
        closedir(auctions);
        return TRUE;
    }

    closedir(auctions);
    return FALSE;
}

/**
 * Check if the auction with the argument aid is still active (within its time frame).
 * Return 1 if it is, 0 if it is not, -1 if an error has occured.
 * DOES NOT ADD END_aid.txt file
*/
int auction_is_active(char *aid) {
    char start_path[27], end_path[25], buff[128];
    char timeactive_str[6], start_fulltime_str[21];
    FILE *start;
    time_t timeactive, start_fulltime, time_elapsed;

    sprintf(start_path, "AUCTIONS/%s/START_%s.txt", aid, aid);
    sprintf(end_path, "AUCTIONS/%s/END_%s.txt", aid, aid);

    if(access(end_path, F_OK) == 0)
        return FALSE;
    
    start = fopen(start_path, "r");
    if(start == NULL) {
        printf("auction_is_active ERROR: Couldn't open START_%s.txt file.\n", aid);
        return -1;
    }
    if (fread(buff, 1, 128, start) == -1) {
        printf("auction_is_active ERROR: Couldn't read START_%s.txt file.\n", aid);
        fclose(start);
        return -1;
    }
    fclose(start);

    sscanf(buff, "%*s %*s %*s %*s %s %*s %s", timeactive_str, start_fulltime_str);

    sprintf(timeactive_str, "%ld", timeactive);
    sprintf(start_fulltime_str, "%ld", start_fulltime);

    time(&time_elapsed);
    time_elapsed -= start_fulltime;

    if(time_elapsed >= timeactive)
        return FALSE;
    else
        return TRUE;
}

/**
 * Check if the user with the argument uid hosts the auction with the argument aid.
 * Return 1 if they do, 0 otherwise.
*/
int user_hosts_auction(char *uid, char *aid) {
    char hosted_path[28];

    sprintf(hosted_path, "USERS/%s/HOSTED/%s.txt", uid, aid);

    return access(hosted_path, F_OK) == 0;
}

/**
 * Check if the bid is higher than the start value of the auction with the argument aid.
 * Return 1 if it is, 0 otherwise.
*/
int bid_higher_than_start_value(char *aid, int bid) {
    char start_path[27], buff[128];
    FILE *start;
    int start_value;

    sprintf(start_path, "AUCTIONS/%s/START_%s.txt", aid, aid);
    
    start = fopen(start_path, "r");
    if(start == NULL) {
        printf("auction_is_active ERROR: Couldn't open START_%s.txt file.\n", aid);
        return -1;
    }
    if (fread(buff, 1, 128, start) == -1) {
        printf("auction_is_active ERROR: Couldn't read START_%s.txt file.\n", aid);
        fclose(start);
        return -1;
    }
    fclose(start);

    sscanf(buff, "%*s %*s %*s %d", start_value);
    return bid > start_value;
}

/**
 * Check if the bid is the highest for the auction with the argument aid.
 * Return 1 if it is, 0 otherwise, -1 for errors.
*/
int bid_is_highest(char *aid, int bid) {
    char bids_path[18];
    struct dirent **bids_list;
    int num_bids;

    sprintf(bids_path, "AUCTIONS/%s/BIDS", aid);

    num_bids = scandir(bids_path, &bids_list, NULL, alphasort);

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
 * Copy onto dest_filename the name of the file associated with the auction with the given aid.
*/
void get_auction_filename(char *aid, char *dest_filename) {
    char start_path[27], name_buffer[25], buff[128];
    FILE *start;

    sprintf(start_path, "AUCTIONS/%s/START_%s.txt", aid, aid);
    
    start = fopen(start_path, "r");
    if(start == NULL) {
        printf("auction_is_active ERROR: Couldn't open START_%s.txt file.\n", aid);
        return -1;
    }
    if (fread(buff, 1, 128, start) == -1) {
        printf("auction_is_active ERROR: Couldn't read START_%s.txt file.\n", aid);
        fclose(start);
        return -1;
    }
    fclose(start);

    sscanf(buff, "%*s %*s %s", name_buffer);
    strcpy(dest_filename, name_buffer);
}

/**
 * Return the file's size in bytes.
*/
int get_filesize(const char *filepath) {
    struct stat file_info;

    if(stat(filepath, &file_info) == -1) {
        perror("stat");
        printf("get_filesize ERROR: couldn't find file with path  %s\n", filepath);
        return -1;
    }

    return file_info.st_size;
}

/**
 * Create END_aid.txt file for auction with the argument aid. Adjust end date-time to wether the timeactive has already passed.
*/
void close_auction(char *aid) {
    char start_path[27], end_path[25], buff[128];
    char timeactive_str[6], start_fulltime_str[21], end_date_time_str[20], time_elapsed_str[6];
    FILE *start, *end;
    time_t timeactive, start_fulltime, time_elapsed, end_time;
    struct tm *end_date_time;

    sprintf(start_path, "AUCTIONS/%s/START_%s.txt", aid, aid);
    sprintf(end_path, "AUCTIONS/%s/END_%s.txt", aid, aid);
    
    start = fopen(start_path, "r");
    if(start == NULL) {
        printf("close_auction ERROR: Couldn't open START_%s.txt file.\n", aid);
        return;
    }
    if (fread(buff, 1, 128, start) == -1) {
        printf("close_auction ERROR: Couldn't read START_%s.txt file.\n", aid);
        fclose(start);
        return;
    }
    fclose(start);

    sscanf(buff, "%*s %*s %*s %*s %s %*s %s", timeactive_str, start_fulltime_str);

    sprintf(timeactive_str, "%ld", timeactive);
    sprintf(start_fulltime_str, "%ld", start_fulltime);

    time(&time_elapsed);
    time_elapsed -= start_fulltime;

    if(time_elapsed >= timeactive) {
        end_time = start_fulltime + timeactive;
        time_elapsed = timeactive;
    }
    else
        time(&end_time);

    end_date_time = gmtime(&end_time);
    sprintf(end_date_time_str, "%4d-%02d-%02d %02d:%02d:%02d",
                                end_date_time->tm_year+1900, end_date_time->tm_mon+1, end_date_time->tm_mday,
                                end_date_time->tm_hour, end_date_time->tm_min, end_date_time->tm_sec);
    sprintf(time_elapsed_str, "%ld", time_elapsed);

    memset(buff, 0, 128);
    memcpy(buff, end_date_time_str, 19);
    memcpy(buff + 19, " ", 1);
    memcpy(buff + 20, time_elapsed_str, strlen(time_elapsed_str) + 1);

    end = fopen(end_path, "w");
    if(end == NULL) {
        printf("close_auction ERROR: Couldn't create END_%s.txt file\n", aid);
        return;
    }
    if (fwrite(buff, 1, strlen(buff), end) == -1) {
        printf("close_auction ERROR: Couldn't write to END_%s.txt file\n", aid);
        fclose(end);
        return;
    }
}

/**
 * Server's response to the login command.
*/
void login(char* uid, char* password) {
    char replyCode[] = "RLI";
    size_t len;
    
    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        len = build_reply(replyCode, "ERR", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    if(!user_is_registered(uid)) {
        register_user(uid, password);
        len = build_reply(replyCode, "REG", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    if(!is_users_password(uid, password)) {
        len = build_reply(replyCode, "NOK", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    log_user_in(uid);
    len = build_reply(replyCode, "OK", NULL);
    if (reply(UDP, len) == -1)
        printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
}

void logout(char *uid, char *password) {
    char replyCode[] = "RLO";
    size_t len;

    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        len = build_reply(replyCode, "ERR", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    if(!user_is_registered(uid)) {
        len = build_reply(replyCode, "UNR", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    if(!user_is_logged_in(uid) || !is_users_password(uid, password)) {
        len = build_reply(replyCode, "NOK", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    log_user_out(uid);
    len = build_reply(replyCode, "OK", NULL);
    if (reply(UDP, len) == -1)
        printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
}

void unregister(char *uid, char* password) {
    char replyCode[] = "RLO";
    size_t len;

    //Check the command's syntax
    if (n != 20 || strlen(uid) != 6 || strlen(password) != 8 || !string_is_number(uid) || !string_is_alnum(password)) {
        len = build_reply(replyCode, "ERR", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    if(!user_is_registered(uid)) {
        len = build_reply(replyCode, "UNR", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    if(!user_is_logged_in(uid)) {
        len = build_reply(replyCode, "NOK", NULL);
        if (reply(UDP, len) == -1)
            printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    unregister_user(uid);
    len = build_reply(replyCode, "OK", NULL);
    if (reply(UDP, len) == -1)
        printf("%s ERROR: Couldn't reply through UDP.\nReply buffer contents: %s\n", replyCode, reply_buf);
}

void show_asset(char *aid) {
    char replyCode[] = "RSA";
    char filename[25], filesize[9], file_path[37], *cursor;
    FILE *auction_file;
    size_t len;
    int fsize;

    //Check the command's syntax
    if(n != 7 || strlen(aid) != 3 || !string_is_number(aid)) {
        len = build_reply(replyCode, "ERR", NULL);
        if(reply(TCP, len) == -1)
         printf("%s ERROR: Couldn't reply through TCP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    //Check if auction exists and has an associated file
    if(!auction_exists(aid) || !auction_has_file(aid)) {
        len = build_reply(replyCode, "NOK", NULL);
        if(reply(TCP, len) == -1)
            printf("%s ERROR: Couldn't reply through TCP.\nReply buffer contents: %s\n", replyCode, reply_buf);
        return;
    }

    //Send reply code and ok status
    len = build_reply(replyCode, "OK", NULL);
    reply_buf[len] = ' ';
    reply(TCP, len);

    get_auction_filename(aid, filename);
    sprintf(file_path, "AUCTIONS/%s/%s", aid, filename);
    fsize = get_filesize(file_path);
    sprintf(filesize, "%d", fsize);

    memset(reply_buf, 0, REPLY_SIZE);
    sprintf(reply_buf, "%s %s ", filename, filesize);
    cursor = reply_buf + strlen(reply_buf);

    auction_file = fopen(file_path, "r");
    if(fsize > 0) {
        n = fread(cursor, 1, BUFFER_SIZE - strlen(reply_buf), auction_file);
        if(n == -1) {
            printf("%s ERROR: Couldn't read from auction file.\n", replyCode);
            fclose(auction_file);
            return;
        }

        fsize -= n;

        n = reply(TCP, strlen(filename) + 1 + strlen(filesize) + 1 + n);
        if(n == -1) {
            printf("%s ERROR: Couldn't write to socket.\n", replyCode);
            fclose(auction_file);
            return;
        }
    }
    while(fsize > 0) {
        n = fread(reply_buf, 1, BUFFER_SIZE, auction_file);
        if(n == -1) {
            printf("%s ERROR: Couldn't read from auction file.\n", replyCode);
            fclose(auction_file);
            return;
        }
        fsize -= n;

        //Send the read data through the TCP connection
        if(reply(TCP, n) == -1) {
            printf("%s ERROR: Couldn't write to socket.\n", replyCode);
            fclose(auction_file);
            return;
        }
    }
    fclose(auction_file);
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
            else
                reply_error(UDP);

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
            else
                reply_error(TCP);

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