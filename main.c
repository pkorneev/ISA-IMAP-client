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
int connect_to_server(const char *host, int port, int use_ssl, SSL_CTX **ssl_ctx, SSL **ssl, const char *certfile, const char *certaddr) {
    struct hostent *H = gethostbyname(host);
    if (!H) {
        fprintf(stderr, "Cannot get host by name: %s\n", host);
        return ERROR_INVALID_HOST;
    }

    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Cannot create socket");
        return ERROR_SOCKET_CREATION;
    }

    struct sockaddr_in server_sock;
    server_sock.sin_family = AF_INET;
    server_sock.sin_port = htons(port);
    memcpy(&(server_sock.sin_addr), H->h_addr, H->h_length);

    if (connect(sock, (struct sockaddr *)&server_sock, sizeof(server_sock)) == -1) {
        perror("Cannot connect to server");
        close(sock);
        return ERROR_CONNECTION_FAILED;
    }

 
    if (use_ssl) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        *ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!*ssl_ctx) {
            fprintf(stderr, "SSL_CTX_new failed.\n");
            close(sock);
            return ERROR_SOCKET_CREATION;
        }

        if (certfile || certaddr) {
            if (!SSL_CTX_load_verify_locations(*ssl_ctx, (certfile ? certfile : NULL), (certaddr ? certaddr : NULL))) {
                fprintf(stderr, "Could not load certificates from file '%s' or directory '%s'\n", certfile ? certfile : "none", certaddr ? certaddr : "none");
                SSL_CTX_free(*ssl_ctx);
                close(sock);
                return ERROR_SOCKET_CREATION;
            }
        } else {
            // Use the default certificate location if none is provided
            if (!SSL_CTX_set_default_verify_paths(*ssl_ctx)) {
                fprintf(stderr, "Failed to set default certificate paths\n");
                SSL_CTX_free(*ssl_ctx);
                close(sock);
                return ERROR_SOCKET_CREATION;
            }
        }

        *ssl = SSL_new(*ssl_ctx);
        if (!*ssl) {
            fprintf(stderr, "SSL_new failed.\n");
            SSL_CTX_free(*ssl_ctx);
            close(sock);
            return ERROR_SOCKET_CREATION;
        }

        SSL_set_fd(*ssl, sock);
        if (SSL_connect(*ssl) != 1) {
            fprintf(stderr, "SSL connection failed.\n");
            SSL_free(*ssl);
            SSL_CTX_free(*ssl_ctx);
            close(sock);
            return ERROR_CONNECTION_FAILED;
        }

        // Verify the server's certificate
        if (SSL_get_verify_result(*ssl) != X509_V_OK) {
            fprintf(stderr, "SSL certificate verification failed.\n");
            SSL_shutdown(*ssl);
            SSL_free(*ssl);
            SSL_CTX_free(*ssl_ctx);
            close(sock);
            return ERROR_CONNECTION_FAILED;
        }

    }

    return sock;
}

void send_imap_command(int sockfd, SSL *ssl, const char *command) {
    ssize_t bytes_sent;

    if (ssl) {
        bytes_sent = SSL_write(ssl, command, strlen(command));
        if (bytes_sent <= 0) {
            int ssl_err = SSL_get_error(ssl, bytes_sent);
            fprintf(stderr, "Failed to send command to server (SSL): %d\n", ssl_err);
            exit(EXIT_FAILURE);
        }
    } else {
        bytes_sent = send(sockfd, command, strlen(command), 0);
        if (bytes_sent < 0) {
            perror("Failed to send command to server");
            exit(EXIT_FAILURE);
        }
    }
}

void read_imap_response(int sockfd, SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    do {
        if (ssl) {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_received <= 0) {
                int ssl_err = SSL_get_error(ssl, bytes_received);
                if (ssl_err == SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "SSL connection closed by peer.\n");
                    exit(EXIT_FAILURE);
                } else {
                    fprintf(stderr, "Failed to read response from server (SSL): %d\n", ssl_err);
                    exit(EXIT_FAILURE);
                }
            }
        } else {
            bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received < 0) {
                perror("Failed to read response from server");
                exit(EXIT_FAILURE);
            }
        }

        buffer[bytes_received] = '\0';

    } while (strstr(buffer, "\r\n") == NULL);

    if (!strstr(buffer, "OK")) {
        fprintf(stderr, "Server response error: %s\n", buffer);
        exit(EXIT_FAILURE);
    }
}

void select_mailbox(int sockfd, const char *mailbox,  SSL *ssl) {
    size_t command_length = strlen(mailbox) + 12 + 2 + 1;
    char *select_command = (char *)malloc(command_length);
    if (select_command == NULL) {
        perror("Failed to allocate memory for select command");
        exit(EXIT_FAILURE);
    }
    snprintf(select_command, command_length, "A997 SELECT %s\r\n", mailbox);
    send_imap_command(sockfd, ssl, select_command);
    read_imap_response(sockfd, ssl);
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
        return -1;
    }

    char line[512];
    int line_number = 0;

    while (fgets(line, sizeof(line), uids_map_file)) {
        line_number++;
        line[strcspn(line, "\n")] = 0;

        if (strcmp(line, message_id) == 0) {
            fclose(uids_map_file);
            return line_number;
        }
    }

    fclose(uids_map_file);
    return -1;
}

void fetch_and_save_email(int sockfd, SSL *ssl, int email_id, int headers_only, const char *out_dir) {
    size_t max_command_length = headers_only ? 32 : 23;
    size_t email_id_length = snprintf(NULL, 0, "%d", email_id);
    size_t total_length = max_command_length + 2 * email_id_length + 1;
    char *fetch_command = (char *)malloc(total_length);
    if (fetch_command == NULL) {
        perror("Failed to allocate memory for fetch command");
        exit(EXIT_FAILURE);
    }

    if (headers_only) {
        snprintf(fetch_command, total_length, 
            "A00%dH FETCH %d BODY.PEEK[HEADER]\r\n", email_id, email_id);
    } else {
        snprintf(fetch_command, total_length, 
            "A00%d FETCH %d BODY[]\r\n", email_id, email_id);
    }

    send_imap_command(sockfd, ssl, fetch_command);
    free(fetch_command);

    char buffer[BUFFER_SIZE];
    char message_buffer[BUFFER_SIZE * 4] = {0};
    ssize_t bytes_received;

    char command_tag[64];
    snprintf(command_tag, sizeof(command_tag), "A00%d", email_id);
    
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
        if (ssl) {
            bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        } else {
            bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        }
        if (bytes_received < 0) {
            perror("Failed to fetch email");
            fclose(uids_map_file);
            return;
        }

        buffer[bytes_received] = '\0';
        strcat(message_buffer, buffer);

        if (!message_id_found) {
            char *message_id_header = strstr(message_buffer, "Message-ID: ");
            if (message_id_header) {
                message_id_start = strchr(message_id_header, '<');
                char *message_id_end = strchr(message_id_header, '>');

                if (message_id_start && message_id_end && message_id_start < message_id_end) {
                    message_id_start++;
                    *message_id_end = '\0';
                    message_id_found = 1;

                    char line[512];
                    int found = 0;
                    rewind(uids_map_file);

                    char temp_message_id[512];
                    if (headers_only) {
                        snprintf(temp_message_id, sizeof(temp_message_id), "%s-H", message_id_start);
                    } else {
                        snprintf(temp_message_id, sizeof(temp_message_id), "%s", message_id_start);
                    }

                    while (fgets(line, sizeof(line), uids_map_file)) {
                        line[strcspn(line, "\n")] = 0;
                        if (strcmp(line, temp_message_id) == 0) {
                            found = 1;
                            break;
                        }
                    }

                    if (!found) {
                        isNewEmail = 1;
                        fprintf(uids_map_file, "%s\n", temp_message_id);
                        fflush(uids_map_file);
                    }

                    line_index = get_message_id_line_index(uids_map_path, temp_message_id);

                    *message_id_end = '>';
                }
            }
        }

        if (strstr(buffer, command_tag) && (strstr(buffer, "OK") || strstr(buffer, "NO") || strstr(buffer, "BAD"))) {
            break;
        }

        memset(buffer, 0, sizeof(buffer));
    }

    char *first_newline = strchr(message_buffer, '\n');
    if (first_newline) {
        memmove(message_buffer, first_newline + 1, strlen(first_newline));
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
    
    char file_path[512];
    if (line_index > 0) {
        snprintf(file_path, sizeof(file_path), "%s/email_%d.eml", out_dir, line_index);
    } else {
        snprintf(file_path, sizeof(file_path), "%s/email_%d.eml", out_dir, email_id);
    }
    
    file = fopen(file_path, "w");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }
    if (isNewEmail) {
        fprintf(file, "%s", message_buffer);
        downloaded_mails_cnt++;
    }
    
    fflush(file);
    fclose(file);
    fclose(uids_map_file);
}

// Search and fetch emails (UNSEEN if new_only is set)
void search_and_fetch_emails(int sockfd, SSL *ssl, int new_only, int headers_only, const char *out_dir) {
    char search_command[512];
    snprintf(search_command, sizeof(search_command), "A998 SEARCH %s\r\n", new_only ? "UNSEEN" : "ALL");
    send_imap_command(sockfd, ssl, search_command);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    if (ssl) {
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    } else {
        bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    }

    if (bytes_received < 0) {
        perror("Failed to search emails");
        return;
    }
    buffer[bytes_received] = '\0';

    char *token = strtok(buffer, " ");
    while (token) {
        if (isdigit(*token)) {
            int email_id = atoi(token);
            fetch_and_save_email(sockfd, ssl, email_id, headers_only, out_dir);
        }
        token = strtok(NULL, " ");
    }
}

int main(int argc, char *argv[]) {
    ImapConfig config;
    AuthData auth;

    parse_args(argc, argv, &config);
    read_auth_file(config.auth_file, &auth);

    int socket_fd;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    socket_fd = connect_to_server(config.server, config.port, config.use_tls, &ssl_ctx, &ssl, config.certfile, config.certaddr);
    if (socket_fd < 0) {
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

    read_imap_response(socket_fd, ssl);

    char login_command[1024];
    snprintf(login_command, sizeof(login_command), "A999 LOGIN %s %s\r\n", auth.username, auth.password);
    send_imap_command(socket_fd, ssl, login_command);
    read_imap_response(socket_fd, ssl);

    select_mailbox(socket_fd, config.mailbox, ssl);

    create_output_directory(config.out_dir);

    search_and_fetch_emails(socket_fd, ssl, config.new_only, config.headers_only, config.out_dir);

    printf("Staženo %d zpráv ze schránky %s\n", downloaded_mails_cnt, config.mailbox);

    // Cleanup
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
    }
    close(socket_fd);

    return 0;
}
