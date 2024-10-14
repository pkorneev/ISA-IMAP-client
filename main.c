#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#define BUFFER_SIZE 1048576
#define ERROR_INVALID_HOST 2
#define ERROR_SOCKET_CREATION 3
#define ERROR_CONNECTION_FAILED 4
static int downloaded_mails_cnt = 0;

// IMAP Config struct
typedef struct {
    char *server;
    int port;
    int use_tls;
    char *certfile;
    char *certaddr;
    int new_only;
    int headers_only;
    char *auth_file;
    char *mailbox;
    char *out_dir;
} ImapConfig;

// Authentication Data
typedef struct {
    char username[256];
    char password[256];
} AuthData;

// Read authentication file
void read_auth_file(const char *auth_file, AuthData *auth) {
    FILE *file = fopen(auth_file, "r");
    if (!file) {
        perror("Failed to open auth file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "username = %255s", auth->username) == 1) {
            continue;
        }
        if (sscanf(line, "password = %255s", auth->password) == 1) {
            continue;
        }
    }
    fclose(file);

    if (strlen(auth->username) == 0 || strlen(auth->password) == 0) {
        fprintf(stderr, "Invalid auth file format\n");
        exit(EXIT_FAILURE);
    }
}

// Parse command-line arguments
void parse_args(int argc, char *argv[], ImapConfig *config) {
    config->port = 0;
    config->use_tls = 0;
    config->certfile = NULL;
    config->certaddr = "/etc/ssl/certs";
    config->new_only = 0;
    config->headers_only = 0;
    config->auth_file = NULL;
    config->mailbox = "INBOX";
    config->out_dir = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "p:Tc:C:nha:b:o:")) != -1) {
        switch (opt) {
            case 'p':
                config->port = atoi(optarg);
                break;
            case 'T':
                config->use_tls = 1;
                break;
            case 'c':
                config->certfile = optarg;
                break;
            case 'C':
                config->certaddr = optarg;
                break;
            case 'n':
                config->new_only = 1;
                break;
            case 'h':
                config->headers_only = 1;
                break;
            case 'a':
                config->auth_file = optarg;
                break;
            case 'b':
                config->mailbox = optarg;
                break;
            case 'o':
                config->out_dir = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Server name (IP address or domain) is required\n");
        exit(EXIT_FAILURE);
    }

    config->server = argv[optind];

    if (config->auth_file == NULL || config->out_dir == NULL) {
        fprintf(stderr, "Both -a (auth_file) and -o (out_dir) are required parameters\n");
        exit(EXIT_FAILURE);
    }

    if (config->port == 0) {
        config->port = config->use_tls ? 993 : 143;
    }
}

// Connect to the IMAP server
int connect_to_server(const char *host, int port) {
    struct hostent *H = gethostbyname(host);
    if (!H) {
        fprintf(stderr, "Cannot get host by name: %s\n", host);
        return ERROR_INVALID_HOST;
    }

    // Create socket
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Cannot create socket");
        return ERROR_SOCKET_CREATION;
    }

    // Create sockaddr_in (socket on server)
    struct sockaddr_in server_sock;
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(port);
    memcpy(&(server_sock.sin_addr), H->h_addr, H->h_length);

    // Connect
    if (connect(sock, (struct sockaddr *)&server_sock, sizeof(server_sock)) == -1) {
        perror("Cannot connect to server");
        close(sock);
        return ERROR_CONNECTION_FAILED;
    }

    return sock; // Return the socket descriptor if successful
}

void send_imap_command(int sockfd, const char *command) {
    ssize_t bytes_sent = send(sockfd, command, strlen(command), 0);
    if (bytes_sent < 0) {
        perror("Failed to send command to server");
        exit(EXIT_FAILURE);
    }
}

// Read the server response
void read_imap_response(int sockfd) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    do {
        bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received < 0) {
            perror("Failed to read response from server");
            exit(EXIT_FAILURE);
        }

        buffer[bytes_received] = '\0';  // Null-terminate the response
    } while (strstr(buffer, "\r\n") == NULL);  // Continue until a full response is received

    if (!strstr(buffer, "OK")) {  // Check for OK response
        fprintf(stderr, "Server response error: %s\n", buffer);
        exit(EXIT_FAILURE);
    }
}

void select_mailbox(int sockfd, const char *mailbox) {
    // "A997 SELECT " is 12 characters, plus 2 for "\r\n" and 1 for the null terminator '\0'
    size_t command_length = strlen(mailbox) + 12 + 2 + 1;
    char *select_command = (char *)malloc(command_length);
    if (select_command == NULL) {
        perror("Failed to allocate memory for select command");
        exit(EXIT_FAILURE);
    }
    snprintf(select_command, command_length, "A997 SELECT %s\r\n", mailbox);
    send_imap_command(sockfd, select_command);
    read_imap_response(sockfd);
    free(select_command);
}

void create_output_directory(const char *dir) {
    struct stat st = {0};

    if (stat(dir, &st) == -1) {
        if (mkdir(dir, 0700) != 0) {
            perror("Failed to create output directory");
            exit(EXIT_FAILURE);
        }
    }
}

int get_message_id_line_index(const char *uids_map_path, const char *message_id) {
    FILE *uids_map_file = fopen(uids_map_path, "r");
    if (!uids_map_file) {
        perror("Failed to open uids_map file for reading");
        return -1; // Error opening the file
    }

    char line[512];
    int line_number = 0;

    // Iterate through each line in the file
    while (fgets(line, sizeof(line), uids_map_file)) {
        line_number++;
        // Remove newline character for comparison
        line[strcspn(line, "\n")] = 0;

        // Compare the line with the provided Message-ID
        if (strcmp(line, message_id) == 0) {
            fclose(uids_map_file);
            return line_number; // Return the 1-based line index
        }
    }

    fclose(uids_map_file);
    return -1; // Return -1 if the Message-ID was not found
}

void fetch_and_save_email(int sockfd, int email_id, int headers_only, const char *out_dir) {
    size_t max_command_length = headers_only ? 32 : 23; // Length of the format strings
    size_t email_id_length = snprintf(NULL, 0, "%d", email_id); // Length of the email_id when formatted
    size_t total_length = max_command_length + 2 * email_id_length + 1; // Command length + email_id replacements + null terminator
    char *fetch_command = (char *)malloc(total_length);
    if (fetch_command == NULL) {
        perror("Failed to allocate memory for fetch command");
        exit(EXIT_FAILURE);
    }

    // Format the fetch command
    if (headers_only) {
        snprintf(fetch_command, total_length, 
            "A00%dH FETCH %d BODY.PEEK[HEADER]\r\n", email_id, email_id);
    } else {
        snprintf(fetch_command, total_length, 
            "A00%d FETCH %d BODY[]\r\n", email_id, email_id);
    }

    send_imap_command(sockfd, fetch_command);
    free(fetch_command);

    char buffer[BUFFER_SIZE];
    char message_buffer[BUFFER_SIZE * 4] = {0};  // Larger buffer for handling split responses
    ssize_t bytes_received;

    // Create a command tag for checking responses (e.g., A001)
    char command_tag[64];
    snprintf(command_tag, sizeof(command_tag), "A00%d", email_id);
    
    // Open uids_map file for appending Message-ID
    char uids_map_path[512];
    snprintf(uids_map_path, sizeof(uids_map_path), "%s/uids_map", out_dir);
    FILE *uids_map_file = fopen(uids_map_path, "a+");
    if (!uids_map_file) {
        perror("Failed to open uids_map file");
        return;
    }

    int message_id_found = 0;
    char *message_id_start = NULL;
    int line_index = -1;
    int isNewEmail = 0;

    // Read until we get the response indicating the fetch is complete
    while (1) {
        bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received < 0) {
            perror("Failed to fetch email");
            fclose(uids_map_file);
            return;
        }

        buffer[bytes_received] = '\0'; // Null-terminate the buffer
        strcat(message_buffer, buffer); // Append to the message buffer

        if (!message_id_found) {
            // Search for "Message-ID: " in the accumulated buffer
            char *message_id_header = strstr(message_buffer, "Message-ID: ");
            if (message_id_header) {
                message_id_start = strchr(message_id_header, '<');
                char *message_id_end = strchr(message_id_header, '>');

                if (message_id_start && message_id_end && message_id_start < message_id_end) {
                    message_id_start++; // Move pointer to the start of the message ID
                    *message_id_end = '\0'; // Null-terminate at the closing '>'
                    message_id_found = 1; // Mark Message-ID as found

                    // Check if Message-ID is already in the uids_map file
                    char line[512];
                    int found = 0;
                    rewind(uids_map_file); // Go to the beginning of the uids_map file

                    char temp_message_id[512];
                    if (headers_only) {
                        snprintf(temp_message_id, sizeof(temp_message_id), "%s-H", message_id_start);
                    } else {
                        snprintf(temp_message_id, sizeof(temp_message_id), "%s", message_id_start);
                    }

                    while (fgets(line, sizeof(line), uids_map_file)) {
                        // Remove newline character for comparison
                        line[strcspn(line, "\n")] = 0;
                        if (strcmp(line, temp_message_id) == 0) {
                            found = 1; // Message-ID already exists
                            break;
                        }
                    }

                    // If not found, write the Message-ID to the file
                    if (!found) {
                        isNewEmail = 1;
                        fprintf(uids_map_file, "%s\n", temp_message_id);
                        fflush(uids_map_file);
                    }

                    // Now, retrieve the line index from the uids_map
                    line_index = get_message_id_line_index(uids_map_path, temp_message_id);

                    *message_id_end = '>'; // Restore the end bracket
                }
            }
        }

        // Check for the end of the response
        if (strstr(buffer, command_tag) && (strstr(buffer, "OK") || strstr(buffer, "NO") || strstr(buffer, "BAD"))) {
            break; // Break if we found the specific command tag with OK, NO, or BAD
        }

        // Clear the buffer to handle new data on the next loop iteration
        memset(buffer, 0, sizeof(buffer));
    }

    // Remove the first and last lines from message_buffer
    char *first_newline = strchr(message_buffer, '\n');
    if (first_newline) {
        memmove(message_buffer, first_newline + 1, strlen(first_newline)); // Skip first line
    }

    char *last_newline = strrchr(message_buffer, '\n');
    if (last_newline) {
        *last_newline = '\0';
        char *second_last_newline = strrchr(message_buffer, '\n');
        if (second_last_newline) {
            *second_last_newline = '\0';
            char *third_last_newline = strrchr(message_buffer, '\n');
                if (third_last_newline) {
                    *third_last_newline = '\0';
                }
        }
    }
    strcat(message_buffer, "\n");

    FILE *file;
    
    // Create the output file for the email using line_index
    char file_path[512];
    if (line_index > 0) {
        snprintf(file_path, sizeof(file_path), "%s/email_%d.txt", out_dir, line_index);
    } else {
        // Fallback if line_index is invalid
        snprintf(file_path, sizeof(file_path), "%s/email_%d.txt", out_dir, email_id);
    }
    
    file = fopen(file_path, "w");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }
    if (isNewEmail) {
        fprintf(file, "%s", message_buffer); // Write the received data to the file
        downloaded_mails_cnt++;
    }
    
    fflush(file);
    fclose(file);
    fclose(uids_map_file);
}

// Search and fetch emails (UNSEEN if new_only is set)
void search_and_fetch_emails(int sockfd, int new_only, int headers_only, const char *out_dir) {
    char search_command[512];
    snprintf(search_command, sizeof(search_command), "A998 SEARCH %s\r\n", new_only ? "UNSEEN" : "ALL");
    send_imap_command(sockfd, search_command);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("Failed to search emails");
        return;
    }
    buffer[bytes_received] = '\0';

    char *token = strtok(buffer, " ");
    while (token) {
        if (isdigit(*token)) {
            int email_id = atoi(token);
            fetch_and_save_email(sockfd, email_id, headers_only, out_dir);
        }
        token = strtok(NULL, " ");
    }
}

int main(int argc, char *argv[]) {
    ImapConfig config;
    AuthData auth;

    parse_args(argc, argv, &config);
    read_auth_file(config.auth_file, &auth);

    // Attempt to connect to the server
    int socket_fd = connect_to_server(config.server, config.port);
    if (socket_fd < 0) {
        // Error handling based on returned error codes
        switch (socket_fd) {
            case ERROR_INVALID_HOST:
                fprintf(stderr, "Invalid host: %s\n", config.server);
                break;
            case ERROR_SOCKET_CREATION:
                fprintf(stderr, "Socket creation failed.\n");
                break;
            case ERROR_CONNECTION_FAILED:
                fprintf(stderr, "Connection to server failed.\n");
                break;
        }
        return EXIT_FAILURE;
    }

    read_imap_response(socket_fd);  // Read and discard the initial server greeting

    // Authenticate using LOGIN command
    char login_command[1024];
    snprintf(login_command, sizeof(login_command), "A999 LOGIN %s %s\r\n", auth.username, auth.password);
    send_imap_command(socket_fd, login_command);
    read_imap_response(socket_fd);  // Check if login was successful

    // Select the mailbox (e.g., INBOX)
    select_mailbox(socket_fd, config.mailbox);

    // Ensure the output directory exists
    create_output_directory(config.out_dir);

    // Fetch emails and save them to the output directory
    search_and_fetch_emails(socket_fd, config.new_only, config.headers_only, config.out_dir);

    printf("Staženo %d zpráv ze schránky %s\n", downloaded_mails_cnt, config.mailbox);
    

    // Close the socket when done
    close(socket_fd);

    return 0;
}
