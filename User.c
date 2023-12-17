#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#define TRUE 1
#define FALSE 0

#define DEFAULT_IP "tejo.tecnico.ulisboa.pt"
#define DEFAULT_PORT "58000"
#define GROUP_NUMBER 100

/* Size of char arrays to contain messages received and messages to send, respectively */
#define MAX_BUFFER_SIZE 2200
#define MAX_MESSAGE_SIZE 40

/* Number of digits/chars of message elements */
#define UID_SIZE 6
#define PWORD_SIZE 8
#define AUCTION_NAME_SIZE 10
#define START_VALUE_SIZE 6
#define DURATION_SIZE 5
#define AID_SIZE 3
#define FILENAME_SIZE 24
#define FILESIZE_DIGITS 8
#define STATUS_SIZE 3
#define MAX_ARG_SIZE 24

//Messages' variables
typedef enum {TCP, UDP} protocol;
char buffer[MAX_BUFFER_SIZE], message[MAX_MESSAGE_SIZE];
char status[STATUS_SIZE + 1], userID[UID_SIZE + 1], password[PWORD_SIZE + 1];

//Sockets' variables
int fd_udp, fd_tcp, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res_udp, *res_tcp;
struct sockaddr_in addr;

/**
 * Get address info for UDP and TCP sockets, and open UDP socket.
*/
void initializeSockets(char* ip, char* port) {
    addrlen = sizeof(addr);
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (fd_udp == -1) /*error*/ exit(EXIT_FAILURE);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket

    errcode = getaddrinfo(ip, port, &hints, &res_udp);
    if (errcode != 0) /*error*/ exit(EXIT_FAILURE);

    hints.ai_socktype = SOCK_STREAM; // TCP socket

    errcode = getaddrinfo(ip, port, &hints, &res_tcp);
    if (errcode != 0) /*error*/ exit(EXIT_FAILURE);
}

/**
 * Send the message in the char array "message" to the server, with the specified transport protocol.
 * Afterwards, wait for the server's response, in the same protocol, and write it to the char array "buffer".
 * Automatically extract the status to the char array "status".
 * DOES NOT CLOSE TCP CONNECTION (so that bigger messages, such as files, may continue to be read)
*/
void sendAndListen(protocol p, size_t message_length) {
    if(p == UDP) {
        //Send
        n = sendto(fd_udp, message, message_length, 0, res_udp->ai_addr, res_udp->ai_addrlen);
        if (n == -1) /*error*/ exit(EXIT_FAILURE);

        //Listen to the server's response and record it to buffer
        n = recvfrom(fd_udp, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addrlen);
        if (n == -1) /*error*/ exit(EXIT_FAILURE);
    }
    else if(p == TCP) {
        //Get file descriptor for tcp socket
        fd_tcp = socket(AF_INET, SOCK_STREAM, 0); // TCP socket
        if (fd_tcp == -1) /*error*/ exit(EXIT_FAILURE);

        //Connect socket to server
        n = connect(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
        if(n==-1) /*error*/exit(EXIT_FAILURE);

        //Write to stream socket
        n = write(fd_tcp, message, message_length);
        if(n == -1) /*error*/exit(EXIT_FAILURE);

        //Listen to the server's response and record it to buffer
        n = read(fd_tcp, buffer, MAX_BUFFER_SIZE);
        if(n==-1) /*error*/ exit(EXIT_FAILURE);

    }
    //Get the status from the server's first response
    sscanf(buffer, "%*s %s", status);
}

/**
 * Set global message variables to 0.
*/
void reset_data() {
    memset(buffer, 0, MAX_BUFFER_SIZE);
    memset(message, 0, MAX_MESSAGE_SIZE);
    memset(status, 0, STATUS_SIZE  + 1);
    n = 0;
}

/**
 * Take an array of strings and concatenate them all in the message char array.
 * Return size of message.
*/
size_t build_message(char** args) {
    size_t offset, total = 0;
    char* cursor = message;
    char** arg_cursor = args;

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
 * Print the usage of this program's optional arguments.
*/
void printUsage() {
    fprintf(stderr, "Usage: ./user [-n ASIP] [-p ASport]\n");
    exit(EXIT_FAILURE);
}

/**
 * Login command
*/
void login(char* uid, char* pword) {
    char* args[] = {"LIN", uid, pword, NULL};

    //Parse arguments
    if(strlen(uid) != UID_SIZE || !string_is_number(uid)) {
        printf("Invalid user ID.\n");
        return;
    }

    if(strlen(pword) != PWORD_SIZE || !string_is_alnum(pword)) {
        printf("Invalid password.\n");
        return;
    }
    
    build_message(args);
    sendAndListen(UDP, 20);

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
    else {
        printf("Unknown login status\n");
        printf("%s\n", buffer);
    }
}

/**
 * Logout command
*/
void logout() {
    char* args[] = {"LOU", userID, password, NULL};

    build_message(args);
    sendAndListen(UDP, 20);

    if(strcmp(status, "OK") == 0) {
        printf("Successful logout\n");
        memset(userID, 0, UID_SIZE + 1);
        memset(password, 0, PWORD_SIZE + 1);
    }
    else if(strcmp(status, "NOK") == 0)
        printf("User not logged in\n");
    else if(strcmp(status, "UNR") == 0)
        printf("Unknown user\n");
    else
        printf("Unknown logout status\n");
}

/**
 * Unregister command
*/
void unregister() {
    char* args[] = {"UNR", userID, password, NULL};
   
    build_message(args);
    sendAndListen(UDP, 20);

    if(strcmp(status, "OK") == 0)
        printf("Successful unregister\n");
    else if(strcmp(status, "NOK") == 0)
        printf("Incorrect unregister attempt\n");
    else if(strcmp(status, "UNR") == 0)
        printf("Unknown user\n");
    else
        printf("Unknown unregister status:\n");
}

/**
 * Show asset command
*/
void show_asset(char* aid) {
    char* args[] = {"SAS", aid, NULL};
    char  *startOfFile, filename[FILENAME_SIZE + 1], fsize[FILESIZE_DIGITS + 1];
    int file_size, remainingData, bytesBeforeFile;
    size_t message_size;
    FILE *file;

    //Parse arguments
    if(strlen(aid) != AID_SIZE || !string_is_number(aid)) {
        printf("Invalid auction ID.\n");
        return;
    }

    message_size = build_message(args);
    sendAndListen(TCP, message_size);

    if(strcmp(status, "OK") == 0) {
        //Start reading the second part of the reply
        n = read(fd_tcp, buffer, MAX_BUFFER_SIZE);
        if(n==-1) /*error*/ exit(EXIT_FAILURE);

        //From the part of the message already received, get the filename and the its size
        sscanf(buffer, "%s %s", filename, fsize);
        
        //Calculate where in the message does the file data start
        bytesBeforeFile = strlen(filename) + 1 + strlen(fsize) + 1;
        startOfFile = buffer + bytesBeforeFile;

        //Create a file in write mode with the given filename
        file = fopen(filename, "w");
        if(file == NULL) /*error*/ exit(EXIT_FAILURE);

        //Write the already received data
        n = fwrite(startOfFile, sizeof(char), n - bytesBeforeFile, file);
        if(n==-1) /*error*/exit(EXIT_FAILURE);

        //Calculate how much of the file is missing
        file_size = atoi(fsize);
        remainingData = file_size - (n - bytesBeforeFile);

        //While the file is incomplete and the socket still has data to read, keep reading the socket and writing to the file
        while((remainingData > 0) && ((n = read(fd_tcp, buffer, MAX_BUFFER_SIZE)) > 0)) {
            if (fwrite(buffer, sizeof(char), n, file) == -1) /*error*/ exit(EXIT_FAILURE);
            remainingData -= n;
        }

        close(fd_tcp);
        fclose(file);
    }

    else if(strcmp(status, "NOK") == 0)
        printf("%s\n", status);
    else
        printf("Unknown show_asset status\n");
    
}

/**
 * Bid command
*/
void bid(char* aid, char* value) {
    char* args[] = {"BID", userID, password, aid, value, NULL};
    size_t message_size;

    //Parse arguments
    if(strlen(aid) != AID_SIZE || !string_is_number(aid)) {
        printf("Invalid auction ID.\n");
        return;
    }

    if(!string_is_number(value)) {
        printf("Invalid bid value.\n");
        return;
    }
    
    message_size = build_message(args);
    sendAndListen(TCP, message_size);
    close(fd_tcp);

    if(strcmp(status, "ACC") == 0)
        printf("Bid accepted\n");
    else if(strcmp(status, "NOK") == 0)
        printf("Auction %s is not active\n", aid);
    else if(strcmp(status, "NLG") == 0)
        printf("User not logged in\n");
    else if(strcmp(status, "REF") == 0)
        printf("Larger bid already previously placed");
    else if(strcmp(status, "ILG") == 0)
        printf("Cannot place a bid in auction hosted by yourself");
    else
        printf("Unknown bid status\n");
}

/**
 * Read a line from src to dest. A line is any number of chars that contain the specified number of spaces or that end in a newline char.
 * Replaces spaces for tabs.
 * Return the length of the line read.
*/
int getLine(char* src, char* dest, int numOfSpaces) {
    int n = 0;
    while(numOfSpaces > 0) {
        if(*src == ' ') {
            numOfSpaces--;
            dest[n++] = '\t';
        }
        else if(*src == '\n') {
            dest[n] = '\0';
            return n;
        }
        else
            dest[n++] = *src;
        src++;
    }
    dest[n - 1] = '\0';
    return n - 1;
}

/**
 * Auxiliary function for the show record command.
*/
void print_show_record() {
    //Advance to the auction data
    char* cursor = buffer + 7;
    char line[80];

    //Print auction header
    printf("HostUID\tAuction Name\tAsset File Name\tStart Value\tStart Date-Time\tTime Active\n");
    
    //Print auction information
    cursor += getLine(cursor, line, 7);
    printf("%s\n",line);
    
    //Check if end has been reached
    if (*cursor == '\n')
        return;
    
    cursor++;
    
    //If next line is a B line, print header
    if(*cursor == 'B')
        printf(" \tBidderUID\tBid Value\tBid Date-Time\tBid Time\n");
    else if (*cursor == '\n')
        return;
    
    //While there are B lines, print them
    while(*cursor == 'B') {
        //Print B line
        cursor += getLine(cursor, line, 6);
        printf("%s\n",line);

        //Check if end has been reached
        if(*cursor == '\n')
            return;

        cursor++;
    }

    //If function gets here, then there must be an E line
    printf(" \tEnd Date-Time\tTime Active\n");
    getLine(cursor, line, 4);
    printf("%s\n",line);
    return;
}

/**
 * Show record command
*/
void show_record(char* aid) {
    char* args[] = {"SRC", aid, NULL};
    
    //Parse arguments
    if(strlen(aid) != AID_SIZE || !string_is_number(aid)) {
        printf("Invalid auction ID.\n");
        return;
    }

    build_message(args);
    sendAndListen(UDP, 8);

    if(strcmp(status, "NOK") == 0)
        printf("Cannot find a bid for the given AID.\n");
    else if(strcmp(status, "OK") == 0) {
        print_show_record();
    }
}

void print_auctions(char* command) {
    //Advance to the auction data
    char* cursor = buffer + 7;
    char *token = strtok(buffer, " ");
    
    printf("%s ", command);
    
    // Process tokens
    while (token != NULL) {
        // Extract auction number and status
        char auctionNumber[4];
        strcpy(auctionNumber, token);
        token = strtok(NULL, " ");
        int status = atoi(token);

        // Print the corresponding output
        printf("\"%s\" - %s; ", auctionNumber, (status == 1) ? "active" : "inactive");

        // Move to the next token
        token = strtok(NULL, " ");

        printf("\n");
    }
}

/**
 * My auctions command
*/
void my_auctions() {
    char* args[] = {"LMA", userID, NULL};
    build_message(args);
    sendAndListen(UDP, 11);

    if (strcmp(status, "NOK") == 0)
        printf("User %s has not started any auctions.\n", userID);
    else if (strcmp(status, "NLG") == 0) {
        printf("User not logged in.\n");
    }
    else if (strcmp(status, "OK") == 0) {
        print_auctions("My auctions:");
    }
}

/**
 * My bids command
*/
void my_bids() {
    char* args[] = {"LMB", userID, NULL};
    build_message(args);
    sendAndListen(UDP, 11);

    if (strcmp(status, "NOK") == 0)
        printf("User %s has not placed any bids.\n", userID);
    else if (strcmp(status, "NLG") == 0) {
        printf("User not logged in.\n");
    }
    else if (strcmp(status, "OK") == 0) {
        print_auctions("My bids:");
    }
}

/**
 * List command
*/
void list() {
    strcpy(message, "LST\n");
    sendAndListen(UDP, 4);

    if (strcmp(status, "NOK") == 0)
        printf("No auction was yet started.\n");
    else if (strcmp(status, "OK") == 0) {
        print_auctions("List of auctions:");
    }
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
 * Open command
*/
void open(char* name, char* asset_fname, char* start_value, char* timeactive) {
    FILE *auction_file;
    size_t len;
    int fsize = get_filesize(asset_fname);
    char* cursor, fsize2[9];
    sprintf(fsize2, "%d", fsize);
    char* args[] = {"OPA", userID, password, name, start_value, timeactive, asset_fname, fsize2, NULL};
    
    len = build_message(args);
    message[len - 1] = ' ';
    
    fd_tcp = socket(AF_INET, SOCK_STREAM, 0); // TCP socket
    if (fd_tcp == -1) /*error*/ exit(EXIT_FAILURE);

    //Connect socket to server
    n = connect(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
    if(n==-1) /*error*/exit(EXIT_FAILURE);

    auction_file = fopen(asset_fname, "r");

    n = fread(message + len, 1, MAX_MESSAGE_SIZE - len, auction_file);
    if(n == -1) {
        printf("ERROR: Couldn't read from auction file.\n");
        fclose(auction_file);
        close(fd_tcp);
        return;
    }

    fsize -= n;
    
    n = write(fd_tcp, message, len + n);
    if(n==-1) /*error*/exit(EXIT_FAILURE);
    
    while((fsize > 0) && ((n =fread(message, 1, MAX_MESSAGE_SIZE, auction_file)) > 0)) {
        fsize -= n;

        //Send the read data through the TCP connection
        if(write(fd_tcp, message, n) == -1) {
            printf("ERROR: Couldn't write to socket.\n");
            fclose(auction_file);
            return;
        }
    }
    fclose(auction_file);

    n = read(fd_tcp, buffer, MAX_BUFFER_SIZE);
    if(n==-1) /*error*/ exit(EXIT_FAILURE);

    sscanf(buffer, "%*s %s", status);

    if (strcmp(status, "NOK") == 0)
        printf("Auction could not be started\n");
    else if (strcmp(status, "NLG") == 0) {
        printf("User not logged in.\n");
    }
    else if (strcmp(status, "OK") == 0) {
        char* cursor = buffer + 7;
        printf("Auction created (aid: %s)   n", buffer);
    }
    else {
        printf("Buffer contents:\n%s\n", buffer);
    }

    close(fd_tcp);
}

/**
 * Close command
*/
void close_command(char* aid) {
    char* args[] = {"CLS", userID, password, aid, NULL};
    build_message(args);
    sendAndListen(TCP, 24);
    close(fd_tcp);
}

int main(int argc, char *argv[]) {
    char input[128], command[20];
    char arg1[MAX_ARG_SIZE + 1], arg2[MAX_ARG_SIZE + 1], arg3[MAX_ARG_SIZE + 1], arg4[MAX_ARG_SIZE + 1];
    char port[6], *ip = DEFAULT_IP;
    int opt, num = atoi(DEFAULT_PORT) + GROUP_NUMBER;

    sprintf(port, "%d", num);

    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
            case 'n':
                ip = optarg;
                break;
            case 'p':
                strcpy(port, optarg);
                break;
            default:
                printUsage();
                exit(EXIT_FAILURE);
        }
    }

    initializeSockets(ip, port);
    reset_data();

    while (1) {
        printf("Enter a command (or 'exit' to quit): ");
        fflush(stdout);

        fgets(input, 128, stdin);
        sscanf(input, "%s", command);

        if (strcmp(command, "login") == 0) {
            sscanf(input, "%*s %s %s", arg1, arg2);
            login(arg1, arg2);
        }

        else if (strcmp(command, "logout") == 0) {
            logout();
        }

        else if (strcmp(command, "unregister") == 0) {
            unregister();
        }
        
        else if (strcmp(command, "exit") == 0) {
           if (strlen(userID) > 0) {
                printf("Please execute the 'logout' command before exiting.\n");
            } else {
                break;
            }
        }
        
        else if (strcmp(command, "open") == 0) {
            sscanf(input, "%*s %s %s %s %s", arg1, arg2, arg3, arg4);
            open(arg1, arg2, arg3, arg4);
        }

        else if (strcmp(command, "close") == 0) {
            sscanf(input, "%*s %s", arg1);
            close_command(arg1);
        }

        else if (strcmp(command, "myauctions") == 0 || strcmp(command, "ma") == 0)  {
            my_auctions();
        }

        else if (strcmp(command, "mybids") == 0  || strcmp(command, "mb") == 0) {
            my_bids();
        }

        else if (strcmp(command, "list") == 0 || strcmp(command, "l") == 0) {
            list();
        }

        else if (strcmp(command, "show_asset") == 0 || strcmp(command, "sa") == 0) {
            sscanf(input, "%*s %s", arg1);
            show_asset(arg1);
        }

        else if (strcmp(command, "bid") == 0 || strcmp(command, "b") == 0) {
            sscanf(input, "%*s %s %s", arg1, arg2);
            bid(arg1, arg2);
        }

        else if (strcmp(command, "show_record") == 0 || strcmp(command, "sr") == 0) {
            sscanf(input, "%*s %s", arg1);
            show_record(arg1);
        }

        else {
            printf("Unknown command.\n");
        }

        reset_data();
        memset(input, 0, 128);
        memset(command, 0, 20);
        memset(arg1, 0, MAX_ARG_SIZE + 1);
        memset(arg2, 0, MAX_ARG_SIZE + 1);
        memset(arg3, 0, MAX_ARG_SIZE + 1);
        memset(arg4, 0, MAX_ARG_SIZE + 1);
    }

    freeaddrinfo(res_udp);
    freeaddrinfo(res_tcp);
    close(fd_udp);
    return 0;
}
