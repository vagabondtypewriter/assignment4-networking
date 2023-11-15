#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// prototypes
int              main(int argc, const char *argv[]);
static void      setup_signal_handler(void);
static int       socket_create(int domain);
static void      socket_bind(int socket_file_desc, struct sockaddr_storage *addr, in_port_t port);
static void      parse_arguments(int argc, const char *argv[], const char **ip_address, const char **port);
static void      convert_address(const char *address, struct sockaddr_storage *addr);
static void      handle_arguments(const char *ip_address, const char *port_str, in_port_t *port);
static in_port_t parse_in_port_t(const char *str);
static void      socket_close(int socket_file_desc);
static void      start_listening(int server_file_desc, int backlog);
static void      sigint_handler(int signum);
static int       socket_accept_connection(int server_file_desc, struct sockaddr_storage *client_addr, socklen_t *client_addr_len);
static void      handle_connection(int client_socket_file_desc, struct sockaddr_storage *client_addr, int server_file_desc);

// var decl
#define BASE_TEN 10
#define MAX_CONN 128
#define MAX_ARGS 32
#define MAX_LENGTH 256
static volatile sig_atomic_t exit_flag = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

// functions
int main(int argc, const char *argv[])
{
    struct sockaddr_storage addr;
    const char             *port_str;
    in_port_t               port;
    const char             *address;
    int                     server_socket_fd;
    parse_arguments(argc, argv, &address, &port_str);
    handle_arguments(address, port_str, &port);
    convert_address(address, &addr);
    server_socket_fd = socket_create(AF_INET);
    socket_bind(server_socket_fd, &addr, port);
    start_listening(server_socket_fd, MAX_CONN);
    setup_signal_handler();
    while(!exit_flag)
    {
        int                     client_sock_file_desc;
        struct sockaddr_storage client_addr;
        socklen_t               client_addr_len;

        client_addr_len       = sizeof(client_addr);
        client_sock_file_desc = socket_accept_connection(server_socket_fd, &client_addr, &client_addr_len);
        if(client_sock_file_desc == -1)
        {
            if(exit_flag)
            {
                break;
            }
        }
        // handle conn
        handle_connection(client_sock_file_desc, &client_addr, server_socket_fd);
        // close client sock
        printf("Waiting for next connection...\n");
    }
    socket_close(server_socket_fd);
    return 1;
}

/**
 * Function to create a socket
 * @param domain domain as described in socket()
 * @return
 */
static int socket_create(int domain)
{
    int socket_file_desc;
    // create a domain socket for IPv4
    socket_file_desc = socket(domain, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    // exits if an error occurs
    if(socket_file_desc == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // returns socket file descriptor
    return socket_file_desc;
}

/**
 * Function to convert a given ip address string into the correct type
 * @param address Ip address string
 * @param addr store of the IP type
 */
static void convert_address(const char *address, struct sockaddr_storage *addr)
{
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        addr->ss_family = AF_INET;
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        addr->ss_family = AF_INET6;
    }
    else
    {
        perror("Not an IPv4 or IPv6 address");
        exit(EXIT_FAILURE);
    }
}

/**
 * Function to set values from the command line input, exits if either are NULL
 * @param ip_address Input ip address
 * @param port_str Input port string
 * @param port Storage variable for the port
 */
static void handle_arguments(const char *ip_address, const char *port_str, in_port_t *port)
{
    if(ip_address == NULL)
    {
        perror("IP address is NULL");
        exit(EXIT_FAILURE);
    }

    if(port_str == NULL)
    {
        perror("Port string is null");
        exit(EXIT_FAILURE);
    }

    *port = parse_in_port_t(port_str);
}

/**
 * Function to parse a string into a port type
 * @param str string to be parsed
 * @return port type from parsed string
 */
static in_port_t parse_in_port_t(const char *str)
{
    char     *endptr;
    uintmax_t parsed_value;

    errno        = 0;
    parsed_value = strtoumax(str, &endptr, BASE_TEN);

    if(errno != 0)
    {
        perror("Error parsing in_port_t");
        exit(EXIT_FAILURE);
    }

    // Check if there are any non-numeric characters in the input string
    if(*endptr != '\0')
    {
        perror("Invalid characters in port input");
        exit(EXIT_FAILURE);
    }

    // Check if the parsed value is within the valid range for in_port_t
    if(parsed_value > UINT16_MAX)
    {
        perror("port value is out of range");
        exit(EXIT_FAILURE);
    }

    return (in_port_t)parsed_value;
}

/**
 * Function parses arguments and sets the ip address and port variables
 * @param argc
 * @param argv
 * @param ip_address
 * @param port
 */
static void parse_arguments(int argc, const char *argv[], const char **ip_address, const char **port)
{
    if(argc != 3)
    {
        perror("Invalid number of args");
        exit(EXIT_FAILURE);
    }
    *ip_address = argv[1];
    *port       = argv[2];
}

/**
 * Function to bind a socket
 * @param socket_file_desc
 * @param addr
 * @param port
 */
static void socket_bind(int socket_file_desc, struct sockaddr_storage *addr, in_port_t port)
{
    char      addr_str[INET6_ADDRSTRLEN];
    socklen_t addr_len;
    void     *vaddr;
    in_port_t net_port;

    net_port = htons(port);

    if(addr->ss_family == AF_INET)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr_len            = sizeof(*ipv4_addr);
        ipv4_addr->sin_port = net_port;
        vaddr               = (void *)&(((struct sockaddr_in *)addr)->sin_addr);
    }
    else if(addr->ss_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr_len             = sizeof(*ipv6_addr);
        ipv6_addr->sin6_port = net_port;
        vaddr                = (void *)&(((struct sockaddr_in6 *)addr)->sin6_addr);
    }
    else
    {
        perror("Internal error: invalid ss_type of addr");
        exit(EXIT_FAILURE);
    }

    if(inet_ntop(addr->ss_family, vaddr, addr_str, sizeof(addr_str)) == NULL)
    {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    printf("Binding to: %s:%u\n", addr_str, port);

    if(bind(socket_file_desc, (struct sockaddr *)addr, addr_len) == -1)
    {
        perror("Binding failed");
        fprintf(stderr, "Error code: %d\n", errno);
        exit(EXIT_FAILURE);
    }

    printf("Bound to socket: %s:%u\n", addr_str, port);
}

/**
 * Function to close a socket
 * @param socket_file_desc socket to close
 */
static void socket_close(int socket_file_desc)
{
    if(close(socket_file_desc) == -1)
    {
        perror("Error closing socket");
        exit(EXIT_FAILURE);
    }
    else
    {
        printf("Closed server. Address will be freed momentarily\n");
    }
}

/**
 * Function to handle signals from the command line terminal
 */
static void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

#if defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    sa.sa_handler = sigint_handler;
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if(sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Function to handle changing the exit flag
 * @param signum
 */
static void sigint_handler(int signum)
{
    exit_flag = 1;
}

/**
 * Function to enable listening for the server
 * @param server_file_desc server file descriptor
 * @param backlog number of connections the server is allowed to have
 */
static void start_listening(int server_file_desc, int backlog)
{
    if(listen(server_file_desc, backlog) == -1)
    {
        fprintf(stderr, "Error code: %d\n", errno);
        close(server_file_desc);
        exit(EXIT_FAILURE);
    }

    printf("Listening for incoming connections...\n");
}

/**
 * Function to accept client sockets
 * @param server_file_desc
 * @param client_addr
 * @param client_addr_len
 * @return
 */
static int socket_accept_connection(int server_file_desc, struct sockaddr_storage *client_addr, socklen_t *client_addr_len)
{
    int  client_fd;
    char client_host[NI_MAXHOST];
    char client_service[NI_MAXSERV];

    errno     = 0;
    client_fd = accept(server_file_desc, (struct sockaddr *)client_addr, client_addr_len);

    if(client_fd == -1)
    {
        if(errno != EINTR)
        {
            perror("accept failed");
        }

        return -1;
    }

    if(getnameinfo((struct sockaddr *)client_addr, *client_addr_len, client_host, NI_MAXHOST, client_service, NI_MAXSERV, 0) == 0)
    {
        printf("Accepted a new connection from %s:%s\n", client_host, client_service);
    }
    else
    {
        printf("Unable to get client information\n");
    }

    return client_fd;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Function to call execv on a given command and write back to client
 * @param client_socket_file_desc
 * @param client_addr
 * @param server_file_desc
 */
static void handle_connection(int client_socket_file_desc, struct sockaddr_storage *client_addr, int server_file_desc)
{
    long  bytes_rec;
    char  buf[UINT16_MAX];
    pid_t pid;
    int   status;

    printf("waiting to read..\n");
    memset(buf, 0, sizeof(buf));

    if(client_socket_file_desc == -1)
    {
        perror("Invalid client socket file descriptor\n");
        return;
    }

    bytes_rec = recv(client_socket_file_desc, buf, sizeof(buf), 0);

    if(bytes_rec == -1)
    {
        perror("recv req\n");
        close(client_socket_file_desc);
        return;
    }
    pid = fork();
    if(pid == 0)
    {
        // vars for execv
        char       *args[MAX_ARGS];
        const char *path = "/bin/";
        char        full_path[MAX_LENGTH];
        // vars for string parsing
        char *saveptr;
        char *token;
        int   arg_count = 0;
        close(server_file_desc);
        if(dup2(client_socket_file_desc, STDOUT_FILENO) == -1)
        {
            perror("Error using dup2");
            exit(1);
        }
        // tokenize string
        token = strtok_r(buf, " ", &saveptr);
        while(token != NULL)
        {
            long unsigned len;
            args[arg_count] = token;
            arg_count++;

            if(arg_count >= MAX_ARGS)
            {
                // prevent buffer overflow, adjust as needed
                fprintf(stderr, "Too many arguments.\n");
                exit(EXIT_FAILURE);
            }

            // remove newline character from the last token
            len = strlen(args[arg_count - 1]);
            if(len > 0 && args[arg_count - 1][len - 1] == '\n')
            {
                args[arg_count - 1][len - 1] = '\0';
            }

            token = strtok_r(NULL, " ", &saveptr);
        }
        args[arg_count] = NULL;
        strcpy(full_path, path);
        if(arg_count != 0)
        {
            strcat(full_path, args[0]);
        }
        execv(full_path, args);
        perror("execv");
        exit(EXIT_FAILURE);
    }
    else if(pid > 0)
    {
        if(waitpid(pid, &status, 0) == -1)
        {
            perror("error waiting for child\n");
            exit(1);
        }
        close(client_socket_file_desc);
    }
}
